import pytest
from core.utils import validate_target


def test_target_empty_and_none():
    valid, msg = validate_target(None)
    assert not valid
    assert "empty or None" in msg

    valid, msg = validate_target("")
    assert not valid
    assert "empty" in msg

    valid, msg = validate_target("   ")
    assert not valid


def test_target_option_injection_rejected():
    # Targets starting with '-' could inject CLI flags into nmap or sqlmap
    valid, msg = validate_target("-sS")
    assert not valid
    assert "cannot start with '-'" in msg

    valid, msg = validate_target("--help")
    assert not valid

    valid, msg = validate_target("-Pn")
    assert not valid


def test_target_dangerous_shell_characters_rejected():
    dangerous = [
        "example.com; rm -rf /",
        "example.com | id",
        "example.com && whoami",
        "$(cat /etc/passwd)",
        "`id`",
        "example.com > output.txt",
        "example.com\n127.0.0.1",
        "example.com\r\n",
        "example.com\t",
    ]
    for d in dangerous:
        valid, msg = validate_target(d)
        assert not valid, f"Expected '{d}' to be rejected"
        assert "illegal characters" in msg


def test_target_valid_ipv4_and_ipv6():
    valid, res = validate_target("127.0.0.1")
    assert valid
    assert res == "127.0.0.1"

    valid, res = validate_target("192.168.1.100")
    assert valid

    valid, res = validate_target("::1")
    assert valid

    valid, res = validate_target("2001:db8::1")
    assert valid


def test_target_valid_cidr():
    valid, res = validate_target("192.168.1.0/24")
    assert valid
    assert res == "192.168.1.0/24"

    valid, res = validate_target("10.0.0.0/8")
    assert valid


def test_target_valid_hostnames():
    valid, res = validate_target("localhost")
    assert valid

    valid, res = validate_target("example.com")
    assert valid

    valid, res = validate_target("scanme.nmap.org")
    assert valid

    valid, res = validate_target("sub-domain.test-lab.co.uk")
    assert valid


def test_target_valid_urls():
    valid, res = validate_target("http://127.0.0.1:8080/path")
    assert valid
    assert res == "127.0.0.1"

    valid, res = validate_target("https://example.com/api?id=1")
    assert valid
    assert res == "example.com"


def test_target_unsupported_url_schemes():
    valid, msg = validate_target("ftp://example.com")
    assert not valid
    assert "Unsupported URL scheme" in msg

    valid, msg = validate_target("file:///etc/passwd")
    assert not valid
