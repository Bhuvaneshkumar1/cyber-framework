from core.progress_engine import run_with_progress
from modules import recon, scan, web_scan, exploit
from core.logger import log
from core.utils import validate_target, is_target_in_scope
from core.session_manager import is_target_authorized, is_intrusive_allowed
from rich import print


def run_attack_chain(target: str | None, include_exploit: bool = False):
    """
    Automated attack chain pipeline.
    By default, executes non-intrusive phases (Recon -> Scan -> Web Scan).
    The Exploit phase is explicitly opt-in to prevent accidental or unauthorized harm.
    """
    if not target:
        print("[red]Error: Target is not set. Use 'set target <target>' first.[/red]")
        return False

    valid, clean_target = validate_target(target)
    if not valid:
        print(f"[red]Error: Invalid target '{target}': {clean_target}[/red]")
        return False

    if not is_target_authorized(clean_target):
        in_scope, scope_msg = is_target_in_scope(clean_target)
        if not in_scope:
            print(f"[red]Security Policy Violation: {scope_msg}[/red]")
            return False

    print(f"[bold green]Starting Attack Chain for target:[/bold green] [cyan]{clean_target}[/cyan]")
    log(f"Attack chain started for {clean_target}")

    # Phase 1: Recon
    print("\n[bold cyan]===== Recon Phase =====[/bold cyan]\n")
    run_with_progress("Recon Phase", lambda: recon.run(clean_target))

    # Phase 2: Scan
    print("\n[bold cyan]===== Scan Phase =====[/bold cyan]\n")
    run_with_progress("Scan Phase", lambda: scan.run(clean_target))

    # Phase 3: Web Scan
    print("\n[bold cyan]===== Web Scan Phase =====[/bold cyan]\n")
    run_with_progress("Web Scan Phase", lambda: web_scan.run(clean_target))

    # Phase 4: Exploit (Explicit opt-in required)
    should_exploit = include_exploit or is_intrusive_allowed()
    if should_exploit:
        print("\n[bold red]===== Exploit Phase (Intrusive Mode Active) =====[/bold red]\n")
        run_with_progress("Exploit Phase", lambda: exploit.run(clean_target))
    else:
        print("\n[yellow]Notice: Exploit phase skipped. Destructive/intrusive actions require explicit opt-in.[/yellow]")
        print("[yellow]To enable: 'run attack_chain --exploit' or 'set intrusive on'[/yellow]")
        log(f"Exploit phase skipped for {clean_target} (non-intrusive default).")

    log(f"Attack chain completed for {clean_target}")
    print("\n[bold green]Attack Chain Finished.[/bold green]")
    return True