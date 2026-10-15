import pytest
from core.session_manager import (
    set_target,
    get_target,
    set_module,
    get_module,
    clear_session,
    clear_target,
    set_intrusive_allowed,
    is_intrusive_allowed,
    authorize_target,
    is_target_authorized,
)


def setup_function():
    clear_session()


def test_session_target_lifecycle():
    assert get_target() is None

    success, msg = set_target("127.0.0.1")
    assert success
    assert get_target() == "127.0.0.1"

    clear_target()
    assert get_target() is None


def test_session_target_validation():
    success, msg = set_target("invalid;rm -rf")
    assert not success
    assert "Invalid target" in msg
    assert get_target() is None


def test_session_module_selection():
    assert get_module() is None
    set_module("recon")
    assert get_module() == "recon"


def test_session_intrusive_opt_in():
    assert not is_intrusive_allowed()
    set_intrusive_allowed(True)
    assert is_intrusive_allowed()
    set_intrusive_allowed(False)
    assert not is_intrusive_allowed()


def test_session_authorization():
    assert not is_target_authorized("target-box.local")
    authorize_target("target-box.local")
    assert is_target_authorized("target-box.local")
