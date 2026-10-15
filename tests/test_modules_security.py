import pytest
import socket
from unittest.mock import patch, MagicMock
import subprocess
from core.session_manager import clear_session, set_intrusive_allowed, authorize_target
from core.intelligence_engine import analyze, IntelligenceFinding
from modules import exploit, recon, scan, web_scan, intelligence


def setup_function():
    clear_session()


# ==============================================================================
# Intelligence Engine Tests
# ==============================================================================

def test_intelligence_engine_distinguishes_facts_and_possibilities():
    finding = analyze(80)
    assert isinstance(finding, IntelligenceFinding)
    assert finding["service"] == "HTTP"
    assert "listening" in finding["observed"] or "open" in finding["observed"]
    assert "web application" in finding["inferred"].lower()
    # Ensure findings are non-assertive possibilities rather than claims of compromise
    assert isinstance(finding["possibilities"], list)
    assert len(finding["possibilities"]) > 0

    # String conversion must work cleanly
    text = str(finding)
    assert "Observed:" in text
    assert "Inferred:" in text
    assert "Verification Target:" in text


def test_intelligence_engine_unknown_port():
    finding = analyze(9999)
    assert finding["port"] == 9999
    assert "Port-9999" in finding["service"]
    assert "protocol identification" in finding["possibilities"][0]


# ==============================================================================
# Exploit Module Tests
# ==============================================================================

def test_exploit_module_rejects_missing_and_invalid_target():
    res = exploit.run(None)
    assert res["status"] == "error"
    assert not res  # ModuleResult evaluates to False

    res = exploit.run("")
    assert res["status"] == "error"

    res = exploit.run("bad;target | id")
    assert res["status"] == "error"
    assert res["error"] == "invalid_target"


def test_exploit_module_rejects_unauthorized_scope():
    # 8.8.8.8 is outside default scope (localhost, 127.0.0.1)
    res = exploit.run("8.8.8.8")
    assert res["status"] == "unauthorized"
    assert res["error"] == "out_of_scope"


def test_exploit_module_requires_intrusive_opt_in():
    # Target 127.0.0.1 is in scope, but intrusive testing is not authorized
    set_intrusive_allowed(False)
    res = exploit.run("127.0.0.1")
    assert res["status"] == "unauthorized"
    assert res["error"] == "intrusive_mode_disabled"
    assert "intrusive action" in res["message"]


def test_exploit_module_handles_missing_tool():
    set_intrusive_allowed(True)
    with patch("modules.exploit.tool_exists", return_value=False):
        res = exploit.run("127.0.0.1")
        assert res["status"] == "tool_missing"
        assert res["error"] == "tool_not_found"


def test_exploit_module_handles_timeout():
    set_intrusive_allowed(True)
    with patch("modules.exploit.tool_exists", return_value=True), \
         patch("modules.exploit.safe_run_subprocess", return_value=None):
        res = exploit.run("127.0.0.1")
        assert res["status"] == "timeout"
        assert res["error"] == "timeout_or_exec_failure"


def test_exploit_module_success_with_mocked_findings():
    set_intrusive_allowed(True)
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "sqlmap identified the following injection points on http://127.0.0.1\nbanner: MySQL 8.0.25"

    with patch("modules.exploit.tool_exists", return_value=True), \
         patch("modules.exploit.safe_run_subprocess", return_value=mock_proc):
        res = exploit.run("127.0.0.1")
        assert res["status"] == "success"
        assert bool(res) is True
        assert len(res["findings"]) >= 1


# ==============================================================================
# Recon Module Tests
# ==============================================================================

def test_recon_module_rejects_invalid_and_out_of_scope_target():
    res = recon.run(None)
    assert res["status"] == "error"

    res = recon.run("-flag-injection")
    assert res["status"] == "error"

    res = recon.run("unauthorized-public-domain-xyz.com")
    assert res["status"] == "unauthorized"


def test_recon_module_native_dns_fallback_success():
    # 127.0.0.1 is in scope
    with patch("modules.recon.tool_exists", return_value=False):
        res = recon.run("127.0.0.1")
        assert res["status"] == "success"
        assert res["tool"] == "python_socket_dns"
        assert len(res["findings"]) > 0


def test_recon_module_handles_dns_failure():
    authorize_target("nonexistent-test-host.local")
    with patch("modules.recon.tool_exists", return_value=False), \
         patch("socket.getaddrinfo", side_effect=socket.gaierror("Name resolution failed")):
        res = recon.run("nonexistent-test-host.local")
        assert res["status"] == "error"
        assert "Name resolution failed" in res["message"]


# ==============================================================================
# Scan Module Tests
# ==============================================================================

def test_scan_module_rejects_invalid_and_out_of_scope():
    res = scan.run(None)
    assert res["status"] == "error"

    res = scan.run("bad;target")
    assert res["status"] == "error"

    res = scan.run("198.51.100.1")
    assert res["status"] == "unauthorized"


def test_scan_module_native_socket_fallback():
    with patch("modules.scan.tool_exists", return_value=False), \
         patch("modules.scan.run_native_socket_scan", return_value=[{"port": 80, "protocol": "tcp", "state": "open"}]):
        res = scan.run("127.0.0.1")
        assert res["status"] == "success"
        assert res["tool"] == "socket_scanner"
        assert len(res["findings"]) == 1
        assert res["findings"][0]["port"] == 80


def test_scan_module_nmap_parsing():
    mock_output = (
        "Starting Nmap 7.92\n"
        "Nmap scan report for 127.0.0.1\n"
        "PORT    STATE SERVICE\n"
        "22/tcp  open  ssh\n"
        "80/tcp  open  http\n"
        "443/tcp open  https\n"
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = mock_output

    with patch("modules.scan.tool_exists", return_value=True), \
         patch("modules.scan.safe_run_subprocess", return_value=mock_proc):
        res = scan.run("127.0.0.1")
        assert res["status"] == "success"
        assert res["tool"] == "nmap"
        ports = [f["port"] for f in res["findings"]]
        assert 22 in ports
        assert 80 in ports
        assert 443 in ports


# ==============================================================================
# Web Scan Module Tests
# ==============================================================================

def test_web_scan_module_rejects_invalid_and_out_of_scope():
    res = web_scan.run(None)
    assert res["status"] == "error"

    res = web_scan.run("ftp://bad-scheme.com")
    assert res["status"] == "error"

    res = web_scan.run("unauthorized-site.com")
    assert res["status"] == "unauthorized"


def test_web_scan_builtin_inspector_fallback():
    mock_findings = [
        {"scanner": "builtin_http_inspector", "type": "http_status", "details": "HTTP 200"},
        {"scanner": "builtin_http_inspector", "type": "server_banner", "details": "Server: Apache/2.4"}
    ]
    with patch("modules.web_scan.tool_exists", return_value=False), \
         patch("modules.web_scan.inspect_http_headers", return_value=(True, mock_findings, "Output summary")):
        res = web_scan.run("127.0.0.1")
        assert res["status"] == "success"
        assert res["tool"] == "builtin_http_inspector"
        # Finding attribution check
        for f in res["findings"]:
            assert f["scanner"] == "builtin_http_inspector"


# ==============================================================================
# Intelligence Module Tests
# ==============================================================================

def test_intelligence_module_rejects_invalid_and_out_of_scope():
    res = intelligence.run(None)
    assert res["status"] == "error"

    res = intelligence.run("invalid_target_#$&")
    assert res["status"] == "error"

    res = intelligence.run("198.51.100.99")
    assert res["status"] == "unauthorized"


def test_intelligence_module_empirical_data_gathering():
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 0))]), \
         patch("modules.intelligence.tool_exists", return_value=False):
        res = intelligence.run("127.0.0.1")
        assert res["status"] == "success"
        assert len(res["findings"]) >= 1
        # Check empirical evidence labeling
        for f in res["findings"]:
            assert f["nature"] == "observed"
