from core.command_parser import parse_command
from core.session_manager import get_module
from core.module_loader import discover_modules
from rich.console import Console

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory

from core.syntax_highlighter import CyberLexer
from core.console_style import cyber_style

console = Console()
modules = list(discover_modules().keys())
commands = [
    "set",
    "use",
    "run",
    "show",
    "exit",
    "attack_chain",
    "target"
]
command_completer = WordCompleter(
    commands + modules,
    ignore_case=True
)
history = FileHistory("data/command_history.txt")
lexer = CyberLexer()
def start_console():
    console.print("[bold green]Entering Advanced Console Mode[/bold green]")
    while True:
        module = get_module()
        if module:
            prompt_text = f"cyber({module})> "
        else:
            prompt_text = "cyber> "
        cmd = prompt(
            prompt_text,
            completer=command_completer,
            history=history,
            lexer=lexer,
            style=cyber_style
        )
        if cmd.strip() == "exit":
            break
        parse_command(cmd)