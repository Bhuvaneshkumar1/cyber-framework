import datetime
import re
from pathlib import Path
from core.utils import PROJECT_ROOT, get_config

REDACTION_PATTERNS = [
    # Passwords, keys, tokens in key-value format
    (re.compile(r'(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*["\']?([^"\'\s]+)["\']?'), r'\1: [REDACTED]'),
    # Bearer tokens
    (re.compile(r'(?i)\bBearer\s+[a-zA-Z0-9_\-\.]{15,}'), 'Bearer [REDACTED]'),
    # Basic auth embedded in URLs: http(s)://user:password@host
    (re.compile(r'(https?://[^:/@\s]+):[^:@\s]+@'), r'\1:[REDACTED]@'),
]


def redact_sensitive_data(message: str) -> str:
    """Mask sensitive tokens, passwords, and credentials from log messages."""
    if not isinstance(message, str):
        message = str(message)

    redacted = message
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def log(msg: str):
    """Write timestamped, redacted diagnostic message to log file."""
    try:
        cfg = get_config()
        should_redact = cfg.get("logging", {}).get("redact_secrets", True)
        log_file_rel = cfg.get("logging", {}).get("file", "scan.log")
        log_file = PROJECT_ROOT / log_file_rel

        safe_msg = redact_sensitive_data(msg) if should_redact else str(msg)

        # Ensure parent directory exists
        log_file.parent.mkdir(parents=True, exist_ok=True)

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now()} : {safe_msg}\n")
    except Exception as e:
        # Failsafe: logging failure must never terminate application flow
        pass