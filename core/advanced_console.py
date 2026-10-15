import re
from core.man_viewer import open_manual

SAFE_MODULE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_]+$")


def show_man(module: str) -> bool:
    """
    Safely display the manual page for the requested module directly in the console.
    Validates input to prevent command injection and avoids unreliable external terminal spawns.
    """
    if not module or not isinstance(module, str):
        print("Usage: man <module>")
        return False

    module_name = module.strip()
    if not SAFE_MODULE_NAME_REGEX.match(module_name):
        print(f"[!] Invalid module name: '{module_name}'. Names must be alphanumeric.")
        return False

    return open_manual(module_name, pause=False)