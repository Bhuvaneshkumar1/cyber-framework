import pytest
from core.module_loader import discover_modules


def test_discover_modules_returns_dict():
    mods = discover_modules()
    assert isinstance(mods, dict)
    # Built-in modules should all be present
    for expected in ["recon", "scan", "web_scan", "exploit", "intelligence"]:
        assert expected in mods, f"Expected module '{expected}' to be discovered"


def test_discover_modules_interface_validation():
    mods = discover_modules()
    for name, mod in mods.items():
        assert hasattr(mod, "run"), f"Module '{name}' missing 'run' attribute"
        assert callable(getattr(mod, "run")), f"Module '{name}.run' is not callable"
