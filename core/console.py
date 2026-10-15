from core.command_parser import parse_command
from core.session_manager import get_module
from core.module_loader import discover_modules
from core.utils import PROJECT_ROOT
from rich.console import Console

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory

from core.syntax_highlighter import CyberLexer
from core.console_style import cyber_style

console = Console()

history_file = PROJECT_ROOT / "data" / "command_history.txt"
history_file.parent.mkdir(parents=True, exist_ok=True)
history = FileHistory(str(history_file))

lexer = CyberLexer()


def get_command_completer():
    modules = list(discover_modules().keys())
    commands = [
        "set",
        "use",
        "run",
        "show",
        "exit",
        "quit",
        "back",
        "clear",
        "cls",
        "man",
        "help",
        "attack_chain",
        "target",
        "intrusive",
        "modules",
        "info",
        "session",
        "options",
        "config",
        "graph",
        "scans",
        "pipeline",
        "report"
    ]
    return WordCompleter(commands + modules, ignore_case=True)


def start_console():
    console.print("[bold green]Entering Advanced Console Mode[/bold green]")
    console.print("[dim]Type 'help' to view available commands, or 'exit' to quit.[/dim]\n")

    completer = get_command_completer()

    while True:
        module = get_module()
        if module:
            prompt_text = f"cyber({module})> "
        else:
            prompt_text = "cyber> "

        try:
            cmd = prompt(
                prompt_text,
                completer=completer,
                history=history,
                lexer=lexer,
                style=cyber_style
            )
        except KeyboardInterrupt:
            # Cleanly handle Ctrl+C: cancel current line and start a new prompt
            console.print()
            continue
        except EOFError:
            # Cleanly handle Ctrl+D: exit console without stack trace
            console.print("\n[green]Exiting Cyber Framework...[/green]")
            break

        if cmd is None:
            continue

        trimmed = cmd.strip()
        if trimmed in ("exit", "quit"):
            console.print("[green]Exiting Cyber Framework...[/green]")
            break

        if trimmed:
            parse_command(trimmed)