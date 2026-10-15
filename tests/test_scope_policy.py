import pytest
from core.utils import is_target_in_scope
from core.session_manager import clear_session, authorize_target, is_target_authorized


def test_scope_allowed_targets():
    config = {
        "scope": {
            "enforce_scope": True,
            "allowed_targets": ["localhost", "127.0.0.1", "10.0.0.0/24"]
        }
    }

    in_scope, _ = is_target_in_scope("127.0.0.1", config=config)
    assert in_scope

    in_scope, _ = is_target_in_scope("localhost", config=config)
    assert in_scope

    in_scope, _ = is_target_in_scope("10.0.0.50", config=config)
    assert in_scope


def test_scope_unauthorized_target_rejected():
    config = {
        "scope": {
            "enforce_scope": True,
            "allowed_targets": ["127.0.0.1", "localhost"]
        }
    }

    in_scope, msg = is_target_in_scope("8.8.8.8", config=config)
    assert not in_scope
    assert "outside configured scope" in msg

    in_scope, msg = is_target_in_scope("unauthorized-domain.com", config=config)
    assert not in_scope


def test_scope_enforcement_disabled():
    config = {
        "scope": {
            "enforce_scope": False,
            "allowed_targets": []
        }
    }

    in_scope, _ = is_target_in_scope("example.com", config=config)
    assert in_scope


def test_session_level_target_authorization():
    clear_session()
    target = "custom-internal-host.local"

    # Initially unauthorized
    assert not is_target_authorized(target)

    # Explicitly authorize
    authorize_target(target)
    assert is_target_authorized(target)
