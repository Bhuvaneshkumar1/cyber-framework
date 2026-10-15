import os
import importlib
from pathlib import Path
from core.utils import PROJECT_ROOT
from core.logger import log

MODULE_DIR_NAME = "modules"


def discover_modules() -> dict:
    """
    Safely discover and dynamically load all valid security modules from the modules/ directory.
    Validates module interfaces, catches import errors gracefully, and reports broken modules.
    """
    modules = {}
    modules_path = PROJECT_ROOT / MODULE_DIR_NAME

    if not modules_path.exists() or not modules_path.is_dir():
        log(f"Module directory '{modules_path}' not found.")
        print(f"[!] Warning: Modules directory '{modules_path}' does not exist.")
        return modules

    for entry in sorted(os.listdir(modules_path)):
        if not entry.endswith(".py"):
            continue

        if entry.startswith((".", "_")) or entry == "__init__.py":
            continue

        if entry.startswith("test_"):
            continue

        name = entry[:-3]

        if not name.isidentifier():
            log(f"Skipping file '{entry}': Not a valid Python identifier.")
            continue

        try:
            module = importlib.import_module(f"{MODULE_DIR_NAME}.{name}")

            # Validate module interface
            if not hasattr(module, "run") or not callable(getattr(module, "run")):
                log(f"Module '{name}' rejected: Missing callable 'run(target)' interface.")
                print(f"[!] Warning: Module '{name}' is missing the required 'run(target)' interface. Skipped.")
                continue

            modules[name] = module
        except Exception as e:
            log(f"Failed to load module '{name}': {e}")
            print(f"[!] Warning: Could not load module '{name}': {e}")

    return modules