from core.session_manager import (
    set_target,
    get_target,
    set_module,
    get_module,
    is_intrusive_allowed,
    set_intrusive_allowed,
    authorize_target,
    is_target_authorized,
)
from core.module_loader import discover_modules
from core.attack_chain import run_attack_chain
from core.pipeline import run_pipeline
from core.attack_graph import show_graph
from core.database import get_scans_by_target, get_all_scans
from core.report import generate_report
from core.utils import clear_terminal, validate_target, is_target_in_scope, get_config
from core.advanced_console import show_man
from rich.console import Console
from rich.table import Table
from core.module_info import module_info

console = Console()

# Discover available modules dynamically
modules = discover_modules()


def get_available_modules() -> dict:
    """Return the currently discovered modules (refreshing if needed)."""
    global modules
    modules = discover_modules()
    return modules


def parse_command(command: str):
    """
    Parse and safely dispatch CLI console commands.
    Protects against malformed input, IndexError crashes, and unvalidated targets.
    """
    if not command or not isinstance(command, str):
        return

    parts = command.strip().split()
    if not parts:
        return

    cmd = parts[0].lower()

    # Help command
    if cmd in ("help", "?"):
        table = Table(title="Cyber Framework Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Example", style="green")

        table.add_row("show modules", "List all available security modules", "show modules")
        table.add_row("show info [module]", "Display detailed info for a module", "show info scan")
        table.add_row("show session", "Display active target and session configuration", "show session")
        table.add_row("show config", "Display active security and scope settings", "show config")
        table.add_row("show graph", "Display attack surface and path visualization", "show graph")
        table.add_row("show scans", "Display recorded SQLite scan database findings", "show scans")
        table.add_row("use <module>", "Select active module, pipeline, or attack_chain", "use recon")
        table.add_row("set target <target>", "Validate and set target IP/domain", "set target 127.0.0.1")
        table.add_row("set intrusive <on|off>", "Toggle authorization for intrusive actions", "set intrusive on")
        table.add_row("run", "Execute currently selected module against target", "run")
        table.add_row("run attack_chain", "Run multi-phase attack chain (--exploit opt-in)", "run attack_chain")
        table.add_row("run pipeline", "Run full multi-stage pipeline (--exploit opt-in)", "run pipeline")
        table.add_row("report [txt|json|html]", "Generate structured assessment report", "report html")
        table.add_row("man <module>", "Read manual documentation for a module", "man scan")
        table.add_row("back", "Deselect active module and return to main prompt", "back")
        table.add_row("clear / cls", "Clear console terminal screen", "clear")
        table.add_row("exit", "Exit Cyber Framework console", "exit")

        console.print(table)
        return

    # Manual command
    if cmd == "man":
        if len(parts) < 2:
            console.print("[yellow]Usage: man <module>[/yellow]")
            return
        show_man(parts[1])
        return

    # Report generation command
    if cmd == "report":
        target = get_target()
        if not target:
            console.print("[red]Error: Target not set. Set a target or run a scan before reporting.[/red]")
            return

        fmt = parts[1].lower() if len(parts) > 1 else "txt"
        scans = get_scans_by_target(target)
        findings_payload = scans if scans else [{"target": target, "status": "active_session", "note": "No port scans recorded in database yet."}]

        success, path_or_err = generate_report(target, findings_payload, output_format=fmt)
        if success:
            console.print(f"[bold green]Report generated successfully:[/bold green] [cyan]{path_or_err}[/cyan]")
        else:
            console.print(f"[red]Report generation failed: {path_or_err}[/red]")
        return

    # Set command
    if cmd == "set":
        if len(parts) < 3:
            console.print("[yellow]Usage: set target <target> | set intrusive <on|off>[/yellow]")
            return

        sub_cmd = parts[1].lower()
        if sub_cmd == "target":
            target_input = parts[2]
            valid, reason = validate_target(target_input)
            if not valid:
                console.print(f"[red]Error: Invalid target '{target_input}': {reason}[/red]")
                return

            in_scope, scope_msg = is_target_in_scope(reason)
            if not in_scope:
                console.print(f"[yellow]Scope Warning: {scope_msg}[/yellow]")
                authorize_target(reason)
                console.print(f"[yellow]Target '{reason}' marked as authorized for this interactive session.[/yellow]")

            success, msg = set_target(reason, validate=False)
            if success:
                console.print(f"[bold green]Target {reason} set[/bold green]")
            else:
                console.print(f"[red]{msg}[/red]")
            return

        elif sub_cmd == "intrusive":
            val = parts[2].lower() in ("on", "true", "yes", "1", "enable")
            set_intrusive_allowed(val)
            status_text = "[bold red]ENABLED[/bold red]" if val else "[bold green]DISABLED[/bold green]"
            console.print(f"Intrusive security testing mode: {status_text}")
            return

        else:
            console.print(f"[yellow]Unknown set parameter '{parts[1]}'. Use 'set target' or 'set intrusive'.[/yellow]")
            return

    # Use command (select module)
    elif cmd == "use":
        if len(parts) < 2:
            console.print("[yellow]Usage: use <module>[/yellow]")
            return

        module = parts[1]
        available = get_available_modules()

        if module in ("attack_chain", "pipeline"):
            set_module(module)
            console.print(f"[bold green]{module.replace('_', ' ').title()} selected[/bold green]")
        elif module in available:
            set_module(module)
            console.print(f"[bold green]Module {module} selected[/bold green]")
        else:
            console.print(f"[red]Module '{module}' not found. Use 'show modules' to view available modules.[/red]")
        return

    # Run attack chain directly
    elif cmd == "run" and len(parts) > 1 and parts[1] == "attack_chain":
        target = get_target()
        if not target:
            console.print("[red]Error: Target not set. Use: set target <target>[/red]")
            return
        include_exploit = "--exploit" in parts
        run_attack_chain(target, include_exploit=include_exploit)
        return

    # Run pipeline directly
    elif cmd == "run" and len(parts) > 1 and parts[1] == "pipeline":
        target = get_target()
        if not target:
            console.print("[red]Error: Target not set. Use: set target <target>[/red]")
            return
        include_exploit = "--exploit" in parts
        run_pipeline(target, include_exploit=include_exploit)
        return

    # Run selected module
    elif cmd == "run":
        module = get_module()
        target = get_target()

        if not target:
            console.print("[red]Error: Target not set. Use: set target <target>[/red]")
            return

        valid, clean_target = validate_target(target)
        if not valid:
            console.print(f"[red]Error: Invalid target '{target}': {clean_target}[/red]")
            return

        if not is_target_authorized(clean_target):
            in_scope, scope_msg = is_target_in_scope(clean_target)
            if not in_scope:
                console.print(f"[red]Security Policy Violation: {scope_msg}[/red]")
                return

        if not module:
            console.print("[yellow]No module selected. Use: use <module>[/yellow]")
            return

        if module == "attack_chain":
            include_exploit = "--exploit" in parts
            run_attack_chain(clean_target, include_exploit=include_exploit)
            return

        if module == "pipeline":
            include_exploit = "--exploit" in parts
            run_pipeline(clean_target, include_exploit=include_exploit)
            return

        available = get_available_modules()
        if module in available:
            # Check intrusive safety policy
            if module == "exploit" and not is_intrusive_allowed():
                console.print("[yellow]Notice: 'exploit' performs intrusive actions against the target.[/yellow]")
                console.print("[yellow]To proceed, enable intrusive mode: 'set intrusive on'[/yellow]")
                return

            available[module].run(clean_target)
        else:
            console.print(f"[red]Selected module '{module}' is not currently available.[/red]")
        return

    # Show command
    elif cmd == "show":
        if len(parts) < 2:
            console.print("[yellow]Usage: show [modules | info <module> | session | config | graph | scans][/yellow]")
            return

        sub_cmd = parts[1].lower()

        if sub_cmd == "modules":
            available = get_available_modules()
            table = Table(title="Available Modules")
            table.add_column("Module Name", style="cyan")
            table.add_column("Type", style="green")

            for m in available:
                if "scan" in m:
                    module_type = "[yellow]Scanner[/yellow]"
                elif "recon" in m:
                    module_type = "[blue]Recon[/blue]"
                elif "exploit" in m:
                    module_type = "[red]Exploit[/red]"
                elif "intelligence" in m:
                    module_type = "[magenta]Intelligence[/magenta]"
                else:
                    module_type = "[green]Utility[/green]"

                table.add_row(f"[bold cyan]{m}[/bold cyan]", module_type)

            table.add_row("[bold cyan]attack_chain[/bold cyan]", "[purple]Attack Chain[/purple]")
            table.add_row("[bold cyan]pipeline[/bold cyan]", "[blue]Full Pipeline[/blue]")
            console.print(table)
            return

        elif sub_cmd == "graph":
            show_graph()
            return

        elif sub_cmd in ("scans", "database"):
            target = get_target()
            records = get_scans_by_target(target) if target else get_all_scans()
            if not records:
                console.print("[yellow]No scan records found in SQLite database.[/yellow]")
                return

            table = Table(title="SQLite Scan Database Records")
            table.add_column("Target", style="cyan")
            table.add_column("Port", style="yellow")
            table.add_column("Service", style="green")
            table.add_column("Recorded Timestamp", style="dim")

            for r in records:
                table.add_row(
                    str(r.get("target", "")),
                    str(r.get("port", "")),
                    str(r.get("service", "")),
                    str(r.get("timestamp", ""))
                )
            console.print(table)
            return

        elif sub_cmd == "info":
            if len(parts) == 3:
                mod_name = parts[2]
            elif len(parts) == 2:
                mod_name = get_module()
                if not mod_name:
                    console.print("[yellow]No module selected. Use: show info <module>[/yellow]")
                    return
            else:
                console.print("[yellow]Usage: show info [module][/yellow]")
                return

            if mod_name in module_info:
                info = module_info[mod_name]
                console.print(f"\n[bold red]Module[/bold red]: {mod_name}")
                console.print(f"[bold red]Tool[/bold red]: {info.get('tool', 'Unknown')}")
                console.print(f"[bold red]Command[/bold red]: {info.get('command', 'Unknown')}")
                if "description" in info:
                    console.print(f"[bold red]Description[/bold red]: {info.get('description')}\n")
            else:
                console.print(f"[yellow]Module '{mod_name}' not found in module info directory.[/yellow]")
            return

        elif sub_cmd in ("session", "options"):
            table = Table(title="Active Session State")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")

            target = get_target() or "[dim]None[/dim]"
            active_mod = get_module() or "[dim]None[/dim]"
            intrusive_status = "[red]Enabled[/red]" if is_intrusive_allowed() else "[green]Disabled (Safe)[/green]"

            table.add_row("Target", str(target))
            table.add_row("Active Module", str(active_mod))
            table.add_row("Intrusive Mode", intrusive_status)
            table.add_row("Authorized", str(is_target_authorized(get_target())))

            console.print(table)
            return

        elif sub_cmd == "config":
            cfg = get_config()
            table = Table(title="Framework Configuration")
            table.add_column("Section", style="cyan")
            table.add_column("Setting", style="yellow")
            table.add_column("Value", style="green")

            for sec, vals in cfg.items():
                if isinstance(vals, dict):
                    for k, v in vals.items():
                        table.add_row(sec, k, str(v))
                else:
                    table.add_row(sec, "", str(vals))

            console.print(table)
            return

        else:
            console.print(f"[yellow]Unknown show option: '{parts[1]}'. Use 'show modules', 'show info', 'show session' (or 'show options'), 'show config', 'show graph', or 'show scans'.[/yellow]")
            return

    # Back command (deselect active module)
    elif cmd == "back":
        set_module(None)
        console.print("[yellow]Cleared active module context.[/yellow]")
        return

    # Clear screen
    elif cmd in ("clear", "cls"):
        clear_terminal()
        return

    # Exit / quit
    elif cmd in ("exit", "quit"):
        import sys
        console.print("[green]Exiting Cyber Framework...[/green]")
        sys.exit(0)

    # Unknown command fallback
    else:
        console.print(f"[yellow]Unknown command: '{command}'. Type 'help' to see available commands.[/yellow]")