import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import ssl

from core.command_parser import parse_command
from core.console import get_command_completer
from core.database import save_port, get_scans_by_target
from core.report import generate_report
from core.session_manager import (
    set_target,
    get_target,
    clear_session,
    set_intrusive_allowed,
    is_intrusive_allowed,
    save_session,
    load_session,
    SESSION_FILE,
)
from core.utils import load_json_file
import modules.recon as recon_module
import modules.web_scan as web_scan_module
import core.attack_graph as attack_graph_module
import core.progress_engine as progress_engine_module


def test_recon_nslookup_ignores_dns_server_header():
    """Verify nslookup parser excludes the local resolver server IP from target findings."""
    nslookup_sample_output = (
        "Server:  UnKnown\n"
        "Address:  10.129.185.238\n\n"
        "Non-authoritative answer:\n"
        "Name:    example.com\n"
        "Address:  93.184.215.14\n"
    )

    mock_result = MagicMock()
    mock_result.stdout = nslookup_sample_output
    mock_result.returncode = 0

    with patch("modules.recon.tool_exists", side_effect=lambda t: t == "nslookup"), \
         patch("modules.recon.safe_run_subprocess", return_value=mock_result), \
         patch("modules.recon.is_target_authorized", return_value=True):

        res = recon_module.run("example.com")
        assert res["status"] == "success"

        finding_values = [f["value"] for f in res["findings"]]
        # Resolver IP must NOT be in findings
        assert "10.129.185.238" not in finding_values
        # Target IP and canonical name MUST be in findings
        assert "93.184.215.14" in finding_values
        assert "example.com" in finding_values


def test_database_no_nested_connection_lock(tmp_path):
    """Verify save_port on uninitialized database does not cause nested connection locking."""
    fresh_db = tmp_path / "fresh_test.db"
    assert not fresh_db.exists()

    success = save_port("127.0.0.1", 8080, "http-alt", db_path=fresh_db)
    assert success is True

    records = get_scans_by_target("127.0.0.1", db_path=fresh_db)
    assert len(records) == 1
    assert records[0]["port"] == 8080
    assert records[0]["service"] == "http-alt"


def test_command_parser_exit_and_quit():
    """Verify parse_command gracefully exits on exit and quit commands."""
    with pytest.raises(SystemExit) as exc1:
        parse_command("exit")
    assert exc1.value.code == 0

    with pytest.raises(SystemExit) as exc2:
        parse_command("quit")
    assert exc2.value.code == 0


def test_console_completer_includes_missing_commands():
    """Verify console completer includes back, clear, cls, options, and quit."""
    completer = get_command_completer()
    words = completer.words
    assert "back" in words
    assert "clear" in words
    assert "cls" in words
    assert "options" in words
    assert "quit" in words


def test_report_generation_handles_none_and_scalar_findings(tmp_path):
    """Verify generate_report handles None, empty, and scalar findings across all formats."""
    # Test None findings
    ok, path_txt = generate_report("127.0.0.1", None, output_format="txt", output_dir=tmp_path)
    assert ok is True
    assert Path(path_txt).exists()

    ok, path_json = generate_report("127.0.0.1", None, output_format="json", output_dir=tmp_path)
    assert ok is True
    assert Path(path_json).exists()

    ok, path_html = generate_report("127.0.0.1", None, output_format="html", output_dir=tmp_path)
    assert ok is True
    assert Path(path_html).exists()

    # Test string findings
    ok, path_str = generate_report("127.0.0.1", "Single text observation", output_format="html", output_dir=tmp_path)
    assert ok is True
    assert "Single text observation" in Path(path_str).read_text(encoding="utf-8")


def test_web_scan_self_signed_ssl_support():
    """Verify web header inspector configures unverified SSL context for lab testing."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.getcode.return_value = 200
        mock_response.geturl.return_value = "https://127.0.0.1:8443"
        mock_response.info.return_value = {"Server": "TestServer/1.0", "Content-Security-Policy": "default-src 'self'"}
        mock_urlopen.return_value.__enter__.return_value = mock_response

        success, findings, text = web_scan_module.inspect_http_headers("https://127.0.0.1:8443")
        assert success is True

        # Check that context parameter was passed and configured to not verify cert
        _, kwargs = mock_urlopen.call_args
        assert "context" in kwargs
        ctx = kwargs["context"]
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE


def test_attack_graph_text_fallback(capsys):
    """Verify attack graph fallback path functions without Rich."""
    with patch.object(attack_graph_module, "_HAS_RICH", False):
        attack_graph_module.clear_graph()
        attack_graph_module.show_graph()
        captured = capsys.readouterr()
        assert "empty" in captured.out.lower()

        attack_graph_module.add_port(80, target="127.0.0.1", service="http")
        attack_graph_module.show_graph()
        captured2 = capsys.readouterr()
        assert "Attack Surface & Path Graph" in captured2.out
        assert "127.0.0.1" in captured2.out


def test_progress_engine_fallback(capsys):
    """Verify progress engine fallback works without Rich."""
    with patch.object(progress_engine_module, "_HAS_RICH", False):
        res = progress_engine_module.run_with_progress("Test Fallback Task", lambda: 42)
        assert res == 42
        captured = capsys.readouterr()
        assert "Starting: Test Fallback Task" in captured.out
        assert "Completed: Test Fallback Task" in captured.out


def test_session_persistence_lifecycle(tmp_path):
    """Verify session manager synchronizes state to data/sessions.json."""
    clear_session()
    assert get_target() is None

    set_target("127.0.0.1")
    set_intrusive_allowed(True)

    # Inspect persisted JSON
    saved_data = load_json_file(SESSION_FILE, default={})
    assert saved_data.get("target") == "127.0.0.1"
    assert saved_data.get("allow_intrusive") is True

    # Test load_session
    clear_session()
    assert get_target() is None
    assert is_intrusive_allowed() is False
