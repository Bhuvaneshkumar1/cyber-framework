import sys
from io import StringIO
from unittest.mock import patch, MagicMock
import pytest

from ui import banner
import main
from core.command_parser import parse_command
from core.session_manager import (
    clear_session,
    set_target,
    get_target,
    is_intrusive_allowed,
    set_intrusive_allowed,
    is_target_authorized
)
from core.tool_detection import tool_exists, verify_tool_capability, get_tool_guidance
from core.utils import validate_target, is_target_in_scope


def test_banner_fallback_mode():
    """Verify show_banner works in both rich-enabled and pure-text fallback modes."""
    # Test fallback mode
    with patch.object(banner, "_HAS_RICH", False), patch.object(banner, "console", None):
        out = StringIO()
        with patch("sys.stdout", out):
            banner.show_banner()
        output = out.getvalue()
        assert "CYBER SECURITY FRAMEWORK" in output

    # Test rich mode
    with patch.object(banner, "_HAS_RICH", True), patch.object(banner, "console", MagicMock()):
        banner.show_banner()
        assert banner.console.print.called


def test_main_prompt_select_fallback():
    """Verify prompt_select works when questionary is missing or raises an exception."""
    choices = ["Option A", "Option B", "Exit"]

    # Test valid numeric selection
    with patch("builtins.input", side_effect=["1"]):
        with patch.dict(sys.modules, {"questionary": None}):
            res = main.prompt_select("Choose", choices)
            assert res == "Option A"

    # Test exit keyword
    with patch("builtins.input", side_effect=["exit"]):
        with patch.dict(sys.modules, {"questionary": None}):
            res = main.prompt_select("Choose", choices)
            assert res == "Exit"

    # Test KeyboardInterrupt
    with patch("builtins.input", side_effect=KeyboardInterrupt):
        with patch.dict(sys.modules, {"questionary": None}):
            res = main.prompt_select("Choose", choices)
            assert res is None


def test_main_prompt_text_fallback():
    """Verify prompt_text handles normal input and KeyboardInterrupt."""
    with patch("builtins.input", side_effect=["192.168.1.1"]):
        with patch.dict(sys.modules, {"questionary": None}):
            assert main.prompt_text("Enter IP") == "192.168.1.1"

    with patch("builtins.input", side_effect=KeyboardInterrupt):
        with patch.dict(sys.modules, {"questionary": None}):
            assert main.prompt_text("Enter IP") is None


def test_main_prompt_confirm_fallback():
    """Verify prompt_confirm handles positive, negative, and interrupted responses."""
    with patch("builtins.input", side_effect=["y"]):
        with patch.dict(sys.modules, {"questionary": None}):
            assert main.prompt_confirm("Confirm?") is True

    with patch("builtins.input", side_effect=["n"]):
        with patch.dict(sys.modules, {"questionary": None}):
            assert main.prompt_confirm("Confirm?") is False

    with patch("builtins.input", side_effect=["", ""]):
        with patch.dict(sys.modules, {"questionary": None}):
            assert main.prompt_confirm("Confirm?", default=True) is True
            assert main.prompt_confirm("Confirm?", default=False) is False

    with patch("builtins.input", side_effect=KeyboardInterrupt):
        with patch.dict(sys.modules, {"questionary": None}):
            assert main.prompt_confirm("Confirm?") is False


def test_main_beginner_mode_out_of_scope_declined():
    """Ensure beginner mode aborts if user declines out-of-scope authorization."""
    clear_session()
    with patch("main.prompt_text", return_value="10.99.99.99"), \
         patch("main.prompt_confirm", return_value=False), \
         patch("builtins.print") as mock_print:
        main.run_beginner_mode()
        assert not is_target_authorized("10.99.99.99")
        assert any("declined" in str(c).lower() for c in mock_print.call_args_list)


def test_main_beginner_mode_exploit_opt_in_gate():
    """Ensure beginner mode strictly requires explicit confirmation for exploit module."""
    clear_session()
    # User declines exploit confirmation
    with patch("main.prompt_text", return_value="127.0.0.1"), \
         patch("main.prompt_select", return_value="Exploit"), \
         patch("main.prompt_confirm", return_value=False), \
         patch("modules.exploit.run") as mock_exploit_run:
        main.run_beginner_mode()
        assert not is_intrusive_allowed()
        assert not mock_exploit_run.called

    # User confirms exploit confirmation
    with patch("main.prompt_text", return_value="127.0.0.1"), \
         patch("main.prompt_select", return_value="Exploit"), \
         patch("main.prompt_confirm", return_value=True), \
         patch("modules.exploit.run") as mock_exploit_run:
        main.run_beginner_mode()
        assert is_intrusive_allowed()
        assert mock_exploit_run.called


def test_all_cli_non_destructive_commands():
    """Verify every documented non-destructive command executes cleanly through command_parser."""
    clear_session()

    # Commands that output tables or information
    test_commands = [
        "help",
        "?",
        "show modules",
        "show info scan",
        "show info recon",
        "show info web_scan",
        "show info exploit",
        "show info intelligence",
        "show session",
        "show options",
        "show config",
        "show graph",
        "show scans",
        "man scan",
        "man recon",
        "man web_scan",
        "man exploit",
        "man intelligence",
        "set target 127.0.0.1",
        "set intrusive on",
        "set intrusive off",
        "use recon",
        "show info",
        "back",
        "clear",
        "cls",
    ]

    for cmd in test_commands:
        parse_command(cmd)

    assert get_target() == "127.0.0.1"


def test_target_validation_edge_cases():
    """Test target validation against traversal, null bytes, multiline, and URLs."""
    # Directory traversal
    valid, _ = validate_target("../../../etc/passwd")
    assert not valid

    valid, _ = validate_target("..\\windows\\system32")
    assert not valid

    # Null bytes and control characters
    valid, _ = validate_target("127.0.0.1\x00extra")
    assert not valid

    valid, _ = validate_target("127.0.0.1\nwhoami")
    assert not valid

    # Supported and unsupported schemes
    valid, host = validate_target("http://target.local:8080/path?param=1#frag")
    assert valid and host == "target.local"

    valid, _ = validate_target("ftp://target.local")
    assert not valid

    # Valid IPv6
    valid, host = validate_target("::1")
    assert valid and host == "::1"


def test_tool_detection_fallbacks_and_guidance():
    """Verify tool detection handles missing tools and returns proper installation guides."""
    assert not tool_exists("definitely_nonexistent_tool_12345")
    assert not verify_tool_capability("definitely_nonexistent_tool_12345")

    nmap_guide = get_tool_guidance("nmap")
    assert "nmap.org" in nmap_guide

    nikto_guide = get_tool_guidance("nikto")
    assert "nikto" in nikto_guide.lower()

    sqlmap_guide = get_tool_guidance("sqlmap")
    assert "sqlmap" in sqlmap_guide.lower()

    generic_guide = get_tool_guidance("some_random_tool")
    assert "some_random_tool" in generic_guide
