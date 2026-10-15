import platform
import os


def get_os() -> str:
    """Return the normalized operating system name ('windows', 'linux', 'darwin')."""
    return platform.system().lower()


def is_windows() -> bool:
    return get_os() == "windows"


def is_linux() -> bool:
    return get_os() == "linux"


def is_macos() -> bool:
    return get_os() == "darwin"


def is_elevated() -> bool:
    """
    Check whether the current Python process runs with administrative/root privileges.
    Avoids requiring sudo/admin permissions when unprivileged execution suffices.
    """
    try:
        if is_windows():
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0
    except Exception:
        return False