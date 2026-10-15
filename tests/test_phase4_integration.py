import pytest
import sqlite3
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.utils import (
    PROJECT_ROOT,
    load_json_file,
    save_json_file,
    load_config,
    get_config,
)
from core.database import (
    init_db,
    save_port,
    get_scans_by_target,
    get_all_scans,
)
from core.pipeline import run_pipeline
from core.attack_graph import (
    add_target,
    add_port,
    add_finding,
    add_attack,
    get_graph_data,
    show_graph,
    clear_graph,
)
from core.report import generate_report
from core.progress_engine import run_with_progress
from core.scheduler import (
    schedule_scan,
    start_scheduler,
    stop_scheduler,
    is_scheduler_available,
    list_scheduled_jobs,
)
from core.tool_detection import tool_exists, get_tool_guidance, verify_tool_capability
from core.os_detection import get_os, is_elevated
from core.session_manager import clear_session, authorize_target


def setup_function():
    clear_session()
    clear_graph()


# ==============================================================================
# Database Tests (Init, Migration, Validation, Querying)
# ==============================================================================

def test_database_init_migration_and_writes(tmp_path):
    test_db = tmp_path / "test_scan.db"

    # Step 1: Initialize brand new database
    assert init_db(test_db) is True
    assert test_db.exists()

    # Step 2: Validate saving ports
    assert save_port("127.0.0.1", 80, "http", db_path=test_db) is True
    assert save_port("127.0.0.1", 443, "https", db_path=test_db) is True

    # Reject invalid ports
    assert save_port("127.0.0.1", 0, "invalid", db_path=test_db) is False
    assert save_port("127.0.0.1", 70000, "invalid", db_path=test_db) is False
    assert save_port("127.0.0.1", "not_a_port", "invalid", db_path=test_db) is False
    assert save_port("", 80, "http", db_path=test_db) is False

    # Step 3: Query scans
    scans_target = get_scans_by_target("127.0.0.1", db_path=test_db)
    assert len(scans_target) == 2
    assert scans_target[0]["port"] == 80
    assert scans_target[1]["port"] == 443

    all_scans = get_all_scans(db_path=test_db)
    assert len(all_scans) == 2


def test_database_backwards_compatible_migration(tmp_path):
    # Simulate an old database created with legacy schema: (target, port, service)
    legacy_db = tmp_path / "legacy_scan.db"
    with sqlite3.connect(str(legacy_db)) as conn:
        conn.execute("CREATE TABLE scans(target TEXT, port INTEGER, service TEXT)")
        conn.execute("INSERT INTO scans VALUES('192.168.1.1', 22, 'ssh')")
        conn.commit()

    # Run migration init_db on legacy database
    assert init_db(legacy_db) is True

    # Verify column 'timestamp' was added seamlessly without data loss
    with sqlite3.connect(str(legacy_db)) as conn:
        c = conn.cursor()
        c.execute("PRAGMA table_info(scans)")
        cols = [col[1] for col in c.fetchall()]
        assert "timestamp" in cols

        c.execute("SELECT target, port, service FROM scans")
        row = c.fetchone()
        assert row == ("192.168.1.1", 22, "ssh")

    # Verify new writes succeed on migrated database
    assert save_port("192.168.1.1", 80, "http", db_path=legacy_db) is True
    scans = get_scans_by_target("192.168.1.1", db_path=legacy_db)
    assert len(scans) == 2


# ==============================================================================
# JSON File Handling & Atomic Recovery Tests
# ==============================================================================

def test_json_atomic_write_and_recovery(tmp_path):
    test_json = tmp_path / "data.json"

    # Test atomic write
    payload = {"status": "ok", "items": [1, 2, 3]}
    assert save_json_file(test_json, payload) is True
    assert test_json.exists()

    # Test clean read
    loaded = load_json_file(test_json)
    assert loaded == payload

    # Test reading non-existent file
    missing_json = tmp_path / "missing.json"
    assert load_json_file(missing_json, default={"fallback": True}) == {"fallback": True}

    # Test recovery from 0-byte file
    empty_json = tmp_path / "empty.json"
    empty_json.write_text("", encoding="utf-8")
    assert load_json_file(empty_json, default=[]) == []

    # Test recovery from corrupted/malformed JSON
    corrupt_json = tmp_path / "corrupt.json"
    corrupt_json.write_text("{ unquoted_bad_json: 123 ", encoding="utf-8")
    assert load_json_file(corrupt_json, default={"safe": True}) == {"safe": True}


# ==============================================================================
# Pipeline & Result Recording Tests
# ==============================================================================

def test_pipeline_target_validation():
    res = run_pipeline(None)
    assert res["status"] == "error"

    res = run_pipeline("-sV")
    assert res["status"] == "error"

    res = run_pipeline("unauthorized-public-host-xyz.com")
    assert res["status"] == "unauthorized"


def test_pipeline_execution_and_result_persistence():
    results_file = PROJECT_ROOT / "data" / "results.json"
    original_content = results_file.read_text(encoding="utf-8") if results_file.exists() else "[]\n"
    try:
        with patch("modules.recon.run", return_value={"status": "success", "findings": []}), \
             patch("modules.scan.run", return_value={"status": "success", "findings": []}), \
             patch("modules.web_scan.run", return_value={"status": "success", "findings": []}), \
             patch("modules.intelligence.run", return_value={"status": "success", "findings": []}), \
             patch("modules.exploit.run", return_value={"status": "success", "findings": []}):

            res = run_pipeline("127.0.0.1", include_exploit=False)
            assert res["status"] == "success"
            assert "recon" in res["stages"]
            assert "scan" in res["stages"]
            assert "web_scan" in res["stages"]
            assert "intelligence" in res["stages"]
            assert res["stages"]["exploit"]["status"] == "skipped"

            # Verify results were appended to data/results.json
            saved = load_json_file(results_file, default=[])
            assert isinstance(saved, list)
            assert len(saved) >= 1
            assert saved[-1]["target"] == "127.0.0.1"
    finally:
        results_file.write_text(original_content, encoding="utf-8")


# ==============================================================================
# Attack Graph Tests
# ==============================================================================

def test_attack_graph_accurate_relationships():
    clear_graph()
    target = "127.0.0.1"

    add_target(target)
    add_port(80, target=target, service="http")
    add_port(443, target=target, service="https")
    add_finding("Port: 80 (http)", "banner", "Apache/2.4")

    data = get_graph_data()
    nodes = [str(n) for n in data["nodes"]]
    edges = [(str(e[0]), str(e[1])) for e in data["edges"]]

    assert f"Target: {target}" in nodes
    assert "Port: 80 (http)" in nodes
    assert "Port: 443 (https)" in nodes
    assert any("Apache/2.4" in n for n in nodes)

    # Verify actual edges connect target to ports
    assert (f"Target: {target}", "Port: 80 (http)") in edges
    assert (f"Target: {target}", "Port: 443 (https)") in edges

    # show_graph executes cleanly
    show_graph()


# ==============================================================================
# Reporting Tests (txt, json, html with XSS escaping)
# ==============================================================================

def test_report_generation_formats_and_escaping(tmp_path):
    target = "127.0.0.1"
    malicious_finding = {
        "service": "http",
        "raw_banner": "<script>alert('xss')</script><b>injection</b>",
        "note": "Normal test finding"
    }

    # 1. Plain text report
    ok, txt_path = generate_report(target, [malicious_finding], output_format="txt", output_dir=tmp_path)
    assert ok is True
    assert Path(txt_path).exists()
    content = Path(txt_path).read_text(encoding="utf-8")
    assert "CYBER SECURITY ASSESSMENT REPORT" in content

    # 2. JSON report
    ok, json_path = generate_report(target, [malicious_finding], output_format="json", output_dir=tmp_path)
    assert ok is True
    assert Path(json_path).exists()
    json_data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    assert json_data["report_metadata"]["target"] == target

    # 3. HTML report with XSS escaping
    ok, html_path = generate_report(target, [malicious_finding], output_format="html", output_dir=tmp_path)
    assert ok is True
    assert Path(html_path).exists()
    html_content = Path(html_path).read_text(encoding="utf-8")

    # Critical security check: raw HTML tags MUST NOT appear unescaped!
    assert "<script>alert('xss')</script>" not in html_content
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_content
    assert "&lt;b&gt;injection&lt;/b&gt;" in html_content

    # 4. Unsupported format rejection
    ok, err = generate_report(target, [], output_format="pdf", output_dir=tmp_path)
    assert ok is False
    assert "Unsupported report format" in err


# ==============================================================================
# Progress Engine Tests
# ==============================================================================

def test_progress_engine_honest_execution():
    executed = []

    def sample_task():
        executed.append(True)
        return "task_success"

    res = run_with_progress("Baseline Task", sample_task)
    assert res == "task_success"
    assert executed == [True]


def test_progress_engine_preserves_exceptions():
    def failing_task():
        raise RuntimeError("Task execution failed")

    with pytest.raises(RuntimeError, match="Task execution failed"):
        run_with_progress("Failing Task", failing_task)


# ==============================================================================
# Scheduler Tests
# ==============================================================================

def test_scheduler_safety_and_scope():
    if not is_scheduler_available():
        # Cleanly handles missing APScheduler
        job = schedule_scan(lambda t: None, "127.0.0.1")
        assert job is None
    else:
        try:
            # Rejects out-of-scope targets
            job = schedule_scan(lambda t: None, "203.0.113.1")
            assert job is None

            # Schedules allowed target
            job_id = schedule_scan(lambda t: None, "127.0.0.1", interval_minutes=120)
            assert job_id is not None

            jobs = list_scheduled_jobs()
            assert any(j["id"] == job_id for j in jobs)
        finally:
            stop_scheduler()


# ==============================================================================
# Tool & OS Detection Tests
# ==============================================================================

def test_tool_detection_and_guidance():
    # Python executable should exist
    assert tool_exists("python") or tool_exists("python3")
    assert tool_exists("completely_imaginary_tool_12345") is False

    guidance = get_tool_guidance("nmap")
    assert "https://nmap.org" in guidance or "apt install" in guidance

    guidance_unknown = get_tool_guidance("custom_unknown_tool")
    assert "system PATH" in guidance_unknown


def test_os_detection_and_privileges():
    current_os = get_os()
    assert current_os in ("windows", "linux", "darwin")

    # Privilege check must return bool without throwing exceptions
    elevated = is_elevated()
    assert isinstance(elevated, bool)


# ==============================================================================
# Operation Outside Repository Root Test
# ==============================================================================

def test_operation_from_outside_repository_root(tmp_path):
    orig_cwd = os.getcwd()
    try:
        # Change working directory to a separate temporary directory
        os.chdir(str(tmp_path))

        # 1. Config loading resolves to PROJECT_ROOT / config.json
        cfg = get_config()
        assert isinstance(cfg, dict)
        assert "scope" in cfg

        # 2. Database path resolves to PROJECT_ROOT / data / scan.db
        from core.database import get_db_path
        db_p = get_db_path()
        assert PROJECT_ROOT in db_p.parents

        # 3. Module loader still discovers modules
        from core.module_loader import discover_modules
        mods = discover_modules()
        assert "scan" in mods
        assert "recon" in mods
    finally:
        os.chdir(orig_cwd)
