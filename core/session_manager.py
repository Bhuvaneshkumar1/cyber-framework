import datetime
from core.utils import validate_target, is_target_in_scope

session = {
    "target": None,
    "module": None,
    "target_set_at": None,
    "authorized_targets": set(),
    "allow_intrusive": False,
}


def set_target(target: str | None, validate: bool = True) -> tuple[bool, str]:
    """
    Set active session target with validation.
    Returns (success, message).
    """
    if target is None:
        session["target"] = None
        session["target_set_at"] = None
        return True, "Target cleared."

    if validate:
        valid, msg = validate_target(target)
        if not valid:
            return False, f"Invalid target: {msg}"
        clean_target = msg
    else:
        clean_target = target.strip()

    session["target"] = clean_target
    session["target_set_at"] = datetime.datetime.now()
    return True, f"Target {clean_target} set."


def get_target() -> str | None:
    """Retrieve currently active session target."""
    return session["target"]


def clear_target():
    """Clear active target to prevent unintended reuse across different modules."""
    session["target"] = None
    session["target_set_at"] = None


def set_module(module: str | None):
    """Set active module name in session."""
    session["module"] = module


def get_module() -> str | None:
    """Retrieve active module name."""
    return session["module"]


def clear_session():
    """Reset all session states."""
    session["target"] = None
    session["module"] = None
    session["target_set_at"] = None
    session["authorized_targets"] = set()
    session["allow_intrusive"] = False


def is_target_stale(max_age_seconds: int = 3600) -> bool:
    """Check if the currently active target has expired to prevent accidental reuse."""
    set_at = session.get("target_set_at")
    if not set_at or not session.get("target"):
        return True
    elapsed = (datetime.datetime.now() - set_at).total_seconds()
    return elapsed > max_age_seconds


def authorize_target(target: str):
    """Mark a specific target as explicitly authorized for the current session."""
    if target:
        session["authorized_targets"].add(target.strip().lower())


def is_target_authorized(target: str | None) -> bool:
    """Check whether the target was explicitly authorized by the user."""
    if not target:
        return False
    target_clean = target.strip().lower()
    if target_clean in session["authorized_targets"]:
        return True
    in_scope, _ = is_target_in_scope(target)
    return in_scope


def set_intrusive_allowed(allowed: bool):
    """Explicitly opt in or out of intrusive/destructive security actions."""
    session["allow_intrusive"] = bool(allowed)


def is_intrusive_allowed() -> bool:
    """Check if intrusive actions are enabled for the current session."""
    return bool(session.get("allow_intrusive", False))