import shutil
import subprocess
from pathlib import Path

TOOL_INSTALL_GUIDES = {
    "nmap": "Download from https://nmap.org/download.html or install via 'sudo apt install nmap' (Linux) or 'brew install nmap' (macOS).",
    "nikto": "Clone from https://github.com/sullo/nikto or install via 'sudo apt install nikto' (Linux). Requires Perl.",
    "sqlmap": "Install via 'pip install sqlmap' or 'sudo apt install sqlmap' (Linux).",
    "theHarvester": "Install via 'pip install theHarvester' or 'sudo apt install theharvester' (Linux).",
    "whois": "Install via 'sudo apt install whois' (Linux) or download Sysinternals Whois (Windows).",
    "nslookup": "Built into Windows, macOS, and Linux (bind9-dnsutils package)."
}


def tool_exists(tool: str) -> bool:
    """Check if an executable is present in the system PATH or exists as an absolute path."""
    if not tool or not isinstance(tool, str):
        return False
    return shutil.which(tool) is not None or Path(tool).is_file()


def get_tool_guidance(tool: str) -> str:
    """Return helpful installation guidance for missing optional tools."""
    clean = tool.lower().strip()
    return TOOL_INSTALL_GUIDES.get(clean, f"Ensure '{tool}' is installed and present in your system PATH.")


def verify_tool_capability(tool: str, probe_flag: str = "--version", timeout: float = 3.0) -> bool:
    """
    Verify that an executable is not only present in PATH but also callable without immediate OS error.
    """
    if not tool_exists(tool):
        return False
    try:
        res = subprocess.run([tool, probe_flag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return res.returncode in (0, 1)  # Some tools exit 1 on version probe but are functional
    except Exception:
        return False