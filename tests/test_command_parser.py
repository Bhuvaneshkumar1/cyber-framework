import pytest
from core.command_parser import parse_command
from core.session_manager import get_target, get_module, clear_session, is_intrusive_allowed


def setup_function():
    clear_session()


def test_command_parser_empty_and_whitespace():
    # Must not raise exceptions
    parse_command("")
    parse_command("   ")
    parse_command(None)


def test_command_parser_show_no_args_crash_fixed():
    # Previously, running 'show' raised IndexError: list index out of range
    # It must now print usage cleanly without crashing
    parse_command("show")


def test_command_parser_show_valid_options():
    parse_command("show modules")
    parse_command("show info scan")
    parse_command("show info")
    parse_command("show session")
    parse_command("show config")
    parse_command("show invalid_subcommand")


def test_command_parser_set_target_valid():
    parse_command("set target 127.0.0.1")
    assert get_target() == "127.0.0.1"


def test_command_parser_set_target_invalid():
    # Target starting with '-' or with shell metacharacters should be rejected
    parse_command("set target -sS")
    assert get_target() is None

    parse_command("set target test.com;rm")
    assert get_target() is None


def test_command_parser_set_intrusive():
    assert not is_intrusive_allowed()
    parse_command("set intrusive on")
    assert is_intrusive_allowed()
    parse_command("set intrusive off")
    assert not is_intrusive_allowed()


def test_command_parser_use_module():
    parse_command("use scan")
    assert get_module() == "scan"

    parse_command("use attack_chain")
    assert get_module() == "attack_chain"

    parse_command("use nonexistent_module_xyz")
    # Should not set invalid module
    assert get_module() == "attack_chain"


def test_command_parser_help():
    parse_command("help")
    parse_command("?")


def test_command_parser_unknown_command():
    parse_command("foobar_command_123")
