import questionary
from core.utils import clear_terminal
from ui.banner import show_banner
from core.console import start_console
from modules import recon, scan, web_scan, exploit,intelligence
from core.logger import log
from core.attack_chain import run_attack_chain
from core.database import init_db


clear_terminal()
show_banner()

mode = questionary.select(
    "Select Mode",
    choices=[
        "Beginner Mode",
        "Advanced Console",
        "Exit"
    ]
).ask()

if mode == "Advanced Console":
    start_console()

elif mode == "Beginner Mode":

    target = questionary.text("Target IP / Domain").ask()

    choice = questionary.select(
        "Select Operation",
            choices=[
                "Recon",
                "Scan",
                "Web Scan",
                "Exploit",
                "Full Pipeline",
                "Automatic Attack Chain",
                "Exit"
            ]
    ).ask()

    if choice == "Recon":
        log("Recon started")
        recon.run(target)

    elif choice == "Scan":
        log("Scan started")
        scan.run(target)

    elif choice == "Web Scan":
        log("Web scan started")
        web_scan.run(target)

    elif choice == "Exploit":
        log("Exploit started")
        exploit.run(target)
        
    elif choice == "intelligence":
        log("Intelligence started")
        intelligence.run(target)
        
    elif choice== "Automatic Attack Chain":
        log("Automatic attack chain started")
        run_attack_chain(target)
        
    elif choice == "Full Pipeline":
        log("Pipeline started")
        recon.run(target)
        scan.run(target)
        web_scan.run(target)
        exploit.run(target)