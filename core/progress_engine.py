from rich.progress import Progress
from rich.console import Console

console = Console()
def run_with_progress(task_name, func):
    with Progress(console=console) as progress:
        task = progress.add_task(task_name, total=100)
        progress.update(task, advance=30)
        progress.stop()
    console.print()
    func()
    console.print()
    with Progress(console=console) as progress:
        task = progress.add_task(task_name, total=100)
        progress.update(task, advance=100)