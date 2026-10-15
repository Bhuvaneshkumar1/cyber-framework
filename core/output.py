try:
    from rich.console import Console
    from rich.panel import Panel
    _HAS_RICH = True
    console = Console()
except ImportError:
    _HAS_RICH = False
    console = None


def show_output(title, content):
    if _HAS_RICH and console is not None:
        console.print(
            Panel(
                str(content),
                title=str(title),
                border_style="green"
            )
        )
    else:
        print(f"=== {title} ===")
        print(content)
        print("=" * (len(str(title)) + 8))