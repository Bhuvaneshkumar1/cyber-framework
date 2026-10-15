import pytest
from core.logger import redact_sensitive_data


def test_logger_redacts_passwords():
    msg = "User logged in with password: supersecret123 to database"
    redacted = redact_sensitive_data(msg)
    assert "supersecret123" not in redacted
    assert "[REDACTED]" in redacted


def test_logger_redacts_bearer_tokens():
    msg = "Request sent with Authorization: Bearer abcdef1234567890abcdef1234567890"
    redacted = redact_sensitive_data(msg)
    assert "abcdef1234567890abcdef1234567890" not in redacted
    assert "Bearer [REDACTED]" in redacted


def test_logger_redacts_basic_auth_in_urls():
    msg = "Connecting to https://admin:SecretPass123@internal.corp.com:8443/api"
    redacted = redact_sensitive_data(msg)
    assert "SecretPass123" not in redacted
    assert "admin:[REDACTED]@" in redacted


def test_logger_preserves_safe_messages():
    msg = "Scan completed on target 127.0.0.1 successfully"
    redacted = redact_sensitive_data(msg)
    assert redacted == msg
