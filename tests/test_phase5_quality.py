import json
from pathlib import Path
from unittest.mock import patch

from core.command_parser import parse_command
from core.man_viewer import open_manual
from core.module_info import module_info
from core.output import show_output
from core.session_manager import session
from core.syntax_highlighter import CyberLexer
from core.utils import PROJECT_ROOT


def test_man_viewer_all_modules():
    """Verify that all framework modules have valid manual pages that open successfully."""
    expected_modules = ["recon", "scan", "web_scan", "exploit", "intelligence", "attack_chain"]
    for mod in expected_modules:
        assert open_manual(mod, pause=False) is True


def test_man_viewer_traversal_safety():
    """Verify that path traversal attempts in man viewer are sanitized and rejected."""
    traversal_inputs = [
        "../../etc/passwd",
        "../config.json",
        "....//....//exploit",
        "non_existent_module_xyz"
    ]
    for bad_input in traversal_inputs:
        assert open_manual(bad_input, pause=False) is False


def test_man_viewer_invalid_inputs():
    """Verify that empty, None, and non-string inputs are handled gracefully."""
    assert open_manual("", pause=False) is False
    assert open_manual(None, pause=False) is False
    assert open_manual(1234, pause=False) is False


def test_module_info_registry_structure():
    """Verify that module_info contains required documentation keys for all core modules."""
    required_keys = {"tool", "command", "description"}
    expected_modules = ["recon", "scan", "web_scan", "exploit", "intelligence", "attack_chain", "pipeline"]
    for mod in expected_modules:
        assert mod in module_info, f"Module {mod} missing from module_info registry"
        entry = module_info[mod]
        for key in required_keys:
            assert key in entry, f"Key {key} missing from module_info[{mod}]"
            assert isinstance(entry[key], str) and len(entry[key]) > 0


def test_output_formatting_rich_and_fallback(capsys):
    """Verify that show_output prints content properly without crashing."""
    show_output("TEST TITLE", "Test Content Line 1\nTest Content Line 2")
    captured = capsys.readouterr()
    assert "TEST TITLE" in captured.out
    assert "Test Content Line 1" in captured.out


def test_syntax_highlighter_tokenization():
    """Verify that CyberLexer correctly classifies commands, keywords, and text."""
    from prompt_toolkit.document import Document
    lexer = CyberLexer()
    doc = Document("set target 127.0.0.1")
    tokens_fn = lexer.lex_document(doc)
    tokens = tokens_fn(0)
    token_types = [t[0] for t in tokens if t[1].strip()]
    assert "class:command" in token_types  # 'set'
    assert "class:keyword" in token_types  # 'target'
    assert "class:text" in token_types     # '127.0.0.1'


def test_command_parser_reports_and_views(tmp_path):
    """Verify that command parser handles report and graph view commands safely."""
    from core.session_manager import set_target, get_module
    set_target("127.0.0.1")

    # test report subcommands
    parse_command("report txt")
    parse_command("report json")
    parse_command("report html")

    # test show graph and show scans
    parse_command("show graph")
    parse_command("show scans")

    # test show options
    parse_command("show options")

    # test back command
    parse_command("back")
    assert get_module() is None


def test_config_files_structure():
    """Verify config.json and config.example.json match schema expectations."""
    config_path = PROJECT_ROOT / "config.json"
    example_path = PROJECT_ROOT / "config.example.json"

    assert config_path.exists()
    assert example_path.exists()

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    with open(example_path, "r", encoding="utf-8") as f:
        example_cfg = json.load(f)

    for c in [cfg, example_cfg]:
        assert "scope" in c
        assert "safety" in c
        assert "logging" in c
        assert "distributed" in c
        assert isinstance(c["scope"]["allowed_targets"], list)
        assert isinstance(c["safety"]["allow_intrusive_actions"], bool)


def test_license_and_gitignore_present():
    """Verify LICENSE and updated .gitignore exist and have required entries."""
    license_file = PROJECT_ROOT / "LICENSE"
    gitignore_file = PROJECT_ROOT / ".gitignore"

    assert license_file.exists()
    content = license_file.read_text(encoding="utf-8")
    assert "MIT License" in content
    assert "Bhuvaneshkumar" in content

    assert gitignore_file.exists()
    gi_content = gitignore_file.read_text(encoding="utf-8")
    assert ".pytest_cache" in gi_content
    assert "*.db" in gi_content
    assert ".env" in gi_content
