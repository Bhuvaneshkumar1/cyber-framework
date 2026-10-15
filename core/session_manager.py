import datetime
from core.utils import validate_target, is_target_in_scope, save_json_file, load_json_file, PROJECT_ROOT

SESSION_FILE = PROJECT_ROOT / "data" / "sessions.json"

session = {
    "target": None,
    "module": None,
    "target_set_at": None,
    "authorized_targets": set(),
    "allow_intrusive": False,
}


def save_session():
    """Persist current active session state to data/sessions.json."""
    try:
        data = {
            "target": session.get("target"),
            "module": session.get("module"),
            "target_set_at": session["target_set_at"].isoformat() if session.get("target_set_at") else None,
            "allow_intrusive": bool(session.get("allow_intrusive", False))
        }
        save_json_file(SESSION_FILE, data)
    except Exception:
        pass


def load_session():
    """Load persistent session state from data/sessions.json if valid."""
    try:
        data = load_json_file(SESSION_FILE, default={})
        if isinstance(data, dict):
            raw_target = data.get("target")
            if raw_target:
                valid, clean = validate_target(raw_target)
                if valid:
                    session["target"] = clean
            session["module"] = data.get("module")
            session["allow_intrusive"] = bool(data.get("allow_intrusive", False))
            if data.get("target_set_at"):
                try:
                    session["target_set_at"] = datetime.datetime.fromisoformat(data["target_set_at"])
                except Exception:
                    session["target_set_at"] = None
    except Exception:
        pass


def set_target(target: str | None, validate: bool = True) -> tuple[bool, str]:
    """
    Set active session target with validation.
    Returns (success, message).
    """
    if target is None:
        session["target"] = None
        session["target_set_at"] = None
        save_session()
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
    save_session()
    return True, f"Target {clean_target} set."


def get_target() -> str | None:
    """Retrieve currently active session target."""
    return session["target"]


def clear_target():
    """Clear active target to prevent unintended reuse across different modules."""
    session["target"] = None
    session["target_set_at"] = None
    save_session()


def set_module(module: str | None):
    """Set active module name in session."""
    session["module"] = module
    save_session()


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
    save_session()


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
    save_session()


def is_intrusive_allowed() -> bool:
    """Check if intrusive actions are enabled for the current session."""
    return bool(session.get("allow_intrusive", False))