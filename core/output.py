from rich.console import Console
from rich.panel import Panel

console = Console()

def show_output(title, content):
    console.print(
        Panel(
            content,
            title=title,
            border_style="green"
        )
    )