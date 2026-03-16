from core.session_manager import set_target, get_target, set_module, get_module
from core.module_loader import discover_modules
from core.attack_chain import run_attack_chain
from core.utils import clear_terminal
from core.advanced_console import show_man
from rich.console import Console
from rich.table import Table
from core.module_info import module_info

console = Console()

modules = discover_modules()

def parse_command(command):

    parts = command.split()

    if not parts:
        return

    # man command
    if parts[0] == "man":
        if len(parts) < 2:
            print("Usage: man <module>")
            return
        show_man(parts[1])
        return

    # set target
    if parts[0] == "set" and len(parts) > 2 and parts[1] == "target":
        set_target(parts[2])
        print(f"Target {parts[2]} set")

    # select module
    elif parts[0] == "use" and len(parts) > 1:
        module = parts[1]

        if module == "attack_chain":
            set_module("attack_chain")
            print("Attack Chain selected")

        elif module in modules:
            set_module(module)
            print(f"Module {module} selected")

        else:
            print("Module not found")

    # run attack chain
    elif parts[0] == "run" and len(parts) > 1 and parts[1] == "attack_chain":
        target = get_target()
        run_attack_chain(target)

    # run selected module
    elif parts[0] == "run":
        module = get_module()
        target = get_target()

        if module == "attack_chain":
            run_attack_chain(target)

        elif module in modules:
            modules[module].run(target)

        else:
            print("Select module using: use <module>")

    # show modules
    elif parts[0] == "show" and len(parts) > 1 and parts[1] == "modules":

        table = Table(title="Available Modules")
        table.add_column("Module Name", style="cyan")
        table.add_column("Type", style="green")

        for m in modules:

            if "scan" in m:
                module_type = "[yellow]Scanner[/yellow]"

            elif "recon" in m:
                module_type = "[blue]Recon[/blue]"

            elif "exploit" in m:
                module_type = "[red]Exploit[/red]"

            else:
                module_type = "[green]Utility[/green]"

            table.add_row(f"[bold cyan]{m}[/bold cyan]", module_type)

        table.add_row("[bold cyan]attack_chain[/bold cyan]", "[purple]Attack Chain[/purple]")

        console.print(table)


    elif parts[0]=="show" and parts[1]=="info":
        if len(parts)==3:
            module = parts[2]
        elif len(parts)==2:
            module=get_module()
            if not module:
                print("No module selected Use: use <module>")
                return
        else:
            print("Usage : show info [module]")
            return
        
        if module in module_info:
            info = module_info[module]
            console.print(f"\n[red]Module[/red]: {module}\n")
            console.print(f"[red]Tool[/red]: {info['tool']}\n")
            console.print(f"[red]command[/red]: {info['command']}\n")
        else:
            print("Module not found")
    # clear terminal
    elif parts[0] == "clear" or parts[0] == "cls":
        clear_terminal()