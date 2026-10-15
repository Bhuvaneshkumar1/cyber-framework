from rich.console import Console

console = Console()


def run_with_progress(task_name: str, func):
    """
    Execute a security task with an honest, indeterminate status spinner.
    Eliminates deceptive jump-to-percentage completion bars and preserves task return values.
    """
    console.print(f"[bold cyan]Starting:[/bold cyan] {task_name}...")
    try:
        with console.status(f"[bold green]{task_name} in progress...[/bold green]", spinner="dots"):
            result = func()
        console.print(f"[bold green]Completed:[/bold green] {task_name}\n")
        return result
    except Exception as e:
        console.print(f"[bold red]Failed during {task_name}:[/bold red] {e}\n")
        raise