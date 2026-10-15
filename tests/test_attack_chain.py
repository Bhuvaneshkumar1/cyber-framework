import pytest
from unittest.mock import patch
from core.attack_chain import run_attack_chain
from core.session_manager import clear_session, set_intrusive_allowed


def setup_function():
    clear_session()


def test_attack_chain_missing_target():
    result = run_attack_chain(None)
    assert result is False

    result = run_attack_chain("")
    assert result is False


def test_attack_chain_invalid_target():
    result = run_attack_chain("bad;rm -rf")
    assert result is False


def test_attack_chain_default_skips_exploit():
    with patch("modules.recon.run") as mock_recon, \
         patch("modules.scan.run") as mock_scan, \
         patch("modules.web_scan.run") as mock_web, \
         patch("modules.exploit.run") as mock_exploit:

        # Run attack chain against loopback (in scope)
        success = run_attack_chain("127.0.0.1", include_exploit=False)
        assert success is True

        mock_recon.assert_called_once_with("127.0.0.1")
        mock_scan.assert_called_once_with("127.0.0.1")
        mock_web.assert_called_once_with("127.0.0.1")

        # Exploit MUST NOT be called when include_exploit=False (default safe behavior)
        mock_exploit.assert_not_called()


def test_attack_chain_opt_in_includes_exploit():
    with patch("modules.recon.run") as mock_recon, \
         patch("modules.scan.run") as mock_scan, \
         patch("modules.web_scan.run") as mock_web, \
         patch("modules.exploit.run") as mock_exploit:

        # Explicitly opt-in with include_exploit=True
        success = run_attack_chain("127.0.0.1", include_exploit=True)
        assert success is True

        mock_recon.assert_called_once_with("127.0.0.1")
        mock_scan.assert_called_once_with("127.0.0.1")
        mock_web.assert_called_once_with("127.0.0.1")
        mock_exploit.assert_called_once_with("127.0.0.1")
