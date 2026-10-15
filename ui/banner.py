try:
    from rich.console import Console
    from rich.panel import Panel
    _HAS_RICH = True
    console = Console()
except ImportError:
    _HAS_RICH = False
    console = None


def show_banner():
    try:
        import pyfiglet
        banner = pyfiglet.figlet_format("CYBER CLI")
    except ImportError:
        banner = "========================================\n           C Y B E R   C L I            \n========================================"

    if _HAS_RICH and console is not None:
        console.print(f"[green]{banner}[/green]", justify="center")
        console.print(
            Panel.fit(
                "[bold green]CYBER SECURITY FRAMEWORK[/bold green]\n"
                "[red]Offensive Security Toolkit[/red]",
                border_style="green"
            ),
            justify="center"
        )
    else:
        print(banner)
        print("=== CYBER SECURITY FRAMEWORK: Offensive Security Toolkit ===")