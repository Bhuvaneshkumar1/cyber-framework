from rich.console import Console
from rich.panel import Panel
import pyfiglet

console = Console()

def show_banner():
    banner = pyfiglet.figlet_format("CYBER CLI")
    console.print(f"[green]{banner}[/green]",justify="center")
    console.print(
        Panel.fit(
            "[bold green]CYBER SECURITY FRAMEWORK[/bold green]\n"
            "[red]Offensive Security Toolkit[/red]",
            border_style="green"
        ),justify="center"
    )