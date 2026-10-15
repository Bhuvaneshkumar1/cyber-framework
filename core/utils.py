import os
import platform
import json
import re
import ipaddress
import subprocess
import shutil
from pathlib import Path
from urllib.parse import urlparse

# Resolve absolute path to project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_CONFIG = {
    "scope": {
        "enforce_scope": True,
        "allowed_targets": ["localhost", "127.0.0.1", "::1"]
    },
    "safety": {
        "allow_intrusive_actions": False,
        "subprocess_timeout_seconds": 30
    },
    "logging": {
        "file": "scan.log",
        "redact_secrets": True
    },
    "distributed": {
        "enabled": False,
        "bind_host": "127.0.0.1",
        "bind_port": 9090,
        "auth_token": ""
    }
}

# Regex for valid hostnames (RFC 1123)
HOSTNAME_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$"
)

# Forbidden characters that indicate shell injection, path traversal, or option injection
DANGEROUS_CHARS_REGEX = re.compile(r"[\s;&|`$<>\n\r\t\\]")


class ModuleResult(dict):
    """
    Standardized structured result returned by all security modules.
    Inherits from dict for full JSON-serializable compatibility, while
    implementing __bool__ to evaluate as True on 'success' and False on failures.
    """
    def __init__(
        self,
        status: str,
        module: str,
        target: str | None,
        tool: str,
        findings: list | None = None,
        raw_output: str = "",
        message: str = "",
        error: str | None = None,
    ):
        super().__init__(
            status=status,
            module=module,
            target=target,
            tool=tool,
            findings=findings if findings is not None else [],
            raw_output=raw_output,
            message=message,
            error=error,
        )

    def __bool__(self) -> bool:
        return self.get("status") == "success"


def get_project_root() -> Path:
    """Return the absolute path to the project root directory."""
    return PROJECT_ROOT


def load_config() -> dict:
    """
    Safely load config.json. If missing, empty, or malformed, return safe defaults
    and print a non-fatal warning without crashing.
    """
    config_path = PROJECT_ROOT / "config.json"
    if not config_path.exists():
        return dict(DEFAULT_CONFIG)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return dict(DEFAULT_CONFIG)
            data = json.loads(content)
            if not isinstance(data, dict):
                return dict(DEFAULT_CONFIG)
            
            # Merge with defaults to ensure all required keys exist
            merged = dict(DEFAULT_CONFIG)
            for section, values in data.items():
                if isinstance(values, dict) and section in merged:
                    merged[section].update(values)
                else:
                    merged[section] = values
            return merged
    except Exception as e:
        print(f"[!] Warning: Failed to load config.json ({e}). Using safe defaults.")
        return dict(DEFAULT_CONFIG)


def get_config() -> dict:
    """Helper alias to retrieve active configuration."""
    return load_config()


def load_json_file(file_path: Path | str, default=None):
    """
    Safely read and parse a JSON file.
    Returns default if the file is missing, 0 bytes, or malformed JSON, without crashing.
    """
    path = Path(file_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    if not path.exists():
        return default

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return default
            return json.loads(content)
    except Exception as e:
        print(f"[!] Warning: Malformed JSON in {path.name} ({e}). Using fallback default.")
        return default


def save_json_file(file_path: Path | str, data: dict | list) -> bool:
    """
    Atomically write JSON data to disk using a temporary file and atomic rename.
    Guarantees data integrity against partial writes and crashes.
    """
    path = Path(file_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(f"{path.suffix}.tmp")

    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        temp_path.replace(path)
        return True
    except Exception as e:
        print(f"[!] Error: Failed to atomically save JSON to {path.name}: {e}")
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass
        return False



def validate_target(target: str | None) -> tuple[bool, str]:
    """
    Validate target domain, IP, CIDR, or URL.
    Returns (is_valid, error_reason_or_normalized_host).
    """
    if not target or not isinstance(target, str):
        return False, "Target cannot be empty or None"

    # Reject dangerous characters, newlines, carriage returns, and shell metacharacters immediately
    if re.search(r"[\n\r\t;&|`$<>\\]", target):
        return False, "Target contains illegal characters, whitespace, or shell metacharacters"

    target = target.strip()
    if not target:
        return False, "Target cannot be empty"

    # Reject embedded whitespace
    if re.search(r"\s", target):
        return False, "Target contains illegal characters, whitespace, or shell metacharacters"

    # Reject option injection (targets starting with '-' or '/')
    if target.startswith("-") or target.startswith("/"):
        return False, "Target cannot start with '-' or '/'"

    # Check for URL format
    if "://" in target:
        try:
            parsed = urlparse(target)
            if parsed.scheme.lower() not in ("http", "https"):
                return False, f"Unsupported URL scheme: {parsed.scheme}"
            host = parsed.hostname
            if not host:
                return False, "URL does not contain a valid host"
            # Validate extracted host
            return validate_target(host)
        except Exception as e:
            return False, f"Invalid URL structure: {e}"

    # Check for CIDR network (e.g. 192.168.1.0/24)
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return True, target
        except ValueError:
            return False, f"Invalid CIDR network format: '{target}'"

    # Check for IPv4 or IPv6 address
    try:
        ipaddress.ip_address(target)
        return True, target
    except ValueError:
        pass

    # Check for valid hostname / domain
    if len(target) > 253:
        return False, "Target hostname exceeds maximum length of 253 characters"

    if HOSTNAME_REGEX.match(target):
        return True, target

    return False, f"Target '{target}' is not a valid IP address, CIDR, or hostname"


def is_target_in_scope(target: str | None, config: dict | None = None) -> tuple[bool, str]:
    """
    Check if a target satisfies the authorization and scope policy.
    Returns (in_scope, message).
    """
    valid, reason = validate_target(target)
    if not valid:
        return False, reason

    if config is None:
        config = get_config()

    scope_cfg = config.get("scope", {})
    if not scope_cfg.get("enforce_scope", True):
        return True, "Scope enforcement disabled"

    allowed = scope_cfg.get("allowed_targets", ["localhost", "127.0.0.1", "::1"])
    target_clean = reason.lower()

    # Exact match check
    for item in allowed:
        item_clean = item.strip().lower()
        if target_clean == item_clean:
            return True, f"Target '{target}' matches allowed scope item '{item}'"

    # IP / Network match check
    try:
        target_ip = ipaddress.ip_address(target_clean)
        for item in allowed:
            try:
                if "/" in item:
                    net = ipaddress.ip_network(item, strict=False)
                    if target_ip in net:
                        return True, f"Target IP '{target_ip}' in allowed network '{item}'"
                else:
                    if target_ip == ipaddress.ip_address(item):
                        return True, f"Target IP '{target_ip}' matches allowed IP '{item}'"
            except ValueError:
                continue
    except ValueError:
        pass

    return False, (
        f"Target '{target}' is outside configured scope. "
        f"Allowed targets: {', '.join(allowed)}. "
        "Update config.json or authorize explicitly to proceed."
    )


def safe_run_subprocess(
    cmd_args: list[str],
    timeout: int | float | None = None,
    capture_output: bool = True,
    text: bool = True,
    cwd: Path | str | None = None,
    **kwargs
) -> subprocess.CompletedProcess | None:
    """
    Safely execute a command using argument-list subprocess execution (no shell=True).
    Applies timeouts, tool detection, and handles errors gracefully.
    """
    if not cmd_args or not isinstance(cmd_args, list):
        print("[!] Error: Command must be provided as a non-empty list of argument strings.")
        return None

    executable = cmd_args[0]
    # Check if executable exists in PATH or as explicit file
    if not shutil.which(executable) and not Path(executable).exists():
        print(f"[!] Tool '{executable}' is not installed or not found in system PATH.")
        return None

    if timeout is None:
        cfg = get_config()
        timeout = cfg.get("safety", {}).get("subprocess_timeout_seconds", 30)

    try:
        result = subprocess.run(
            cmd_args,
            timeout=timeout,
            capture_output=capture_output,
            text=text,
            cwd=cwd or PROJECT_ROOT,
            check=False,
            **kwargs
        )
        return result
    except subprocess.TimeoutExpired:
        print(f"[!] Command '{executable}' timed out after {timeout} seconds.")
        return None
    except PermissionError:
        print(f"[!] Permission denied executing '{executable}'.")
        return None
    except FileNotFoundError:
        print(f"[!] Tool '{executable}' was not found.")
        return None
    except Exception as e:
        print(f"[!] Error executing '{executable}': {e}")
        return None


def clear_terminal():
    """Clear terminal screen safely across operating systems."""
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")