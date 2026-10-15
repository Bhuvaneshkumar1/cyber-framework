import os
import sys
from pathlib import Path
from core.utils import PROJECT_ROOT

MAN_DIR = PROJECT_ROOT / "man"
GREEN = "\033[32m"
BOLD = "\033[1m"
RESET = "\033[0m"

SECTION_HEADERS = {
    "NAME",
    "DESCRIPTION",
    "UNDERLYING TOOL",
    "EXECUTION",
    "USAGE",
    "MODULE OPTION",
    "COMMANDS",
    "EXAMPLE",
    "OUTPUT",
    "REQUIREMENTS",
    "AUTHOR",
    "VERSION"
}


def open_manual(module: str, pause: bool = False) -> bool:
    """
    Load, format, and display manual page for a given module.
    Returns True if found and displayed, False otherwise.
    """
    if not module or not isinstance(module, str):
        print("Usage: man <module>")
        return False

    if "/" in module or "\\" in module or ".." in module:
        print(f"\nInvalid module name: '{module}'")
        return False

    clean_module = Path(module).name.replace(".man", "")
    path = MAN_DIR / f"{clean_module}.man"

    if not path.exists():
        print(f"\nManual page not found for '{clean_module}' in {MAN_DIR}")
        return False

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        print()
        for line in lines:
            stripped = line.strip()
            if stripped in SECTION_HEADERS:
                print(f"{GREEN}{BOLD}{line}{RESET}", end="")
            else:
                print(f"{GREEN}{line}{RESET}", end="")
        print()

        if pause:
            print("\nPress Enter to return...")
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                pass
        return True
    except Exception as e:
        print(f"Error reading manual page: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m core.man_viewer <module>")
        sys.exit(1)

    found = open_manual(sys.argv[1], pause=False)
    sys.exit(0 if found else 1)