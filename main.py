import sys
from core.utils import clear_terminal, validate_target, is_target_in_scope
from ui.banner import show_banner
from core.console import start_console
from modules import recon, scan, web_scan, exploit, intelligence
from core.logger import log
from core.attack_chain import run_attack_chain
from core.pipeline import run_pipeline
from core.database import init_db
from core.session_manager import set_target, authorize_target, set_intrusive_allowed, is_intrusive_allowed


def prompt_select(message: str, choices: list[str]) -> str | None:
    """Prompt user using questionary if installed, falling back to standard input."""
    try:
        import questionary
        return questionary.select(message, choices=choices).ask()
    except (ImportError, Exception):
        print(f"\n{message}:")
        for i, c in enumerate(choices, 1):
            print(f"  {i}. {c}")
        while True:
            try:
                raw = input(f"Enter choice (1-{len(choices)}) or 'exit': ").strip()
                if raw.lower() in ("exit", "q"):
                    return "Exit"
                if raw.isdigit() and 1 <= int(raw) <= len(choices):
                    return choices[int(raw) - 1]
                print("Invalid selection. Try again.")
            except (KeyboardInterrupt, EOFError):
                return None


def prompt_text(message: str) -> str | None:
    """Prompt user for text using questionary if installed, falling back to input."""
    try:
        import questionary
        return questionary.text(message).ask()
    except (ImportError, Exception):
        try:
            val = input(f"{message}: ").strip()
            return val
        except (KeyboardInterrupt, EOFError):
            return None


def prompt_confirm(message: str, default: bool = False) -> bool:
    """Prompt for yes/no confirmation."""
    try:
        import questionary
        return questionary.confirm(message, default=default).ask()
    except (ImportError, Exception):
        try:
            hint = " [Y/n]: " if default else " [y/N]: "
            val = input(message + hint).strip().lower()
            if not val:
                return default
            return val in ("y", "yes")
        except (KeyboardInterrupt, EOFError):
            return False


def run_beginner_mode():
    raw_target = prompt_text("Target IP / Domain")
    if not raw_target:
        print("No target provided. Exiting.")
        return

    valid, clean_target = validate_target(raw_target)
    if not valid:
        print(f"Error: Invalid target '{raw_target}': {clean_target}")
        return

    in_scope, scope_msg = is_target_in_scope(clean_target)
    if not in_scope:
        print(f"\n[!] Scope Warning: {scope_msg}")
        confirmed = prompt_confirm(f"Authorize target '{clean_target}' for this session?", default=False)
        if not confirmed:
            print("Target authorization declined. Aborting.")
            return
        authorize_target(clean_target)

    set_target(clean_target)

    choice = prompt_select(
        "Select Operation",
        choices=[
            "Recon",
            "Scan",
            "Web Scan",
            "Intelligence",
            "Exploit",
            "Full Pipeline",
            "Automatic Attack Chain",
            "Exit"
        ]
    )

    if not choice or choice == "Exit":
        return

    if choice == "Recon":
        log("Recon started")
        recon.run(clean_target)

    elif choice == "Scan":
        log("Scan started")
        scan.run(clean_target)

    elif choice == "Web Scan":
        log("Web scan started")
        web_scan.run(clean_target)

    elif choice == "Intelligence":
        log("Intelligence started")
        intelligence.run(clean_target)

    elif choice == "Exploit":
        print("\n[!] WARNING: Exploit execution performs intrusive testing against the target.")
        confirm = prompt_confirm("Do you explicitly authorize intrusive testing against this target?", default=False)
        if confirm:
            set_intrusive_allowed(True)
            log("Exploit started")
            exploit.run(clean_target)
        else:
            print("Exploit cancelled: intrusive action not authorized.")

    elif choice == "Automatic Attack Chain":
        print("\nAutomatic Attack Chain runs Recon, Scan, and Web Scan phases.")
        include_exploit = prompt_confirm("Include intrusive Exploit phase in attack chain?", default=False)
        if include_exploit:
            set_intrusive_allowed(True)
        log("Automatic attack chain started")
        run_attack_chain(clean_target, include_exploit=include_exploit)

    elif choice == "Full Pipeline":
        include_exploit = prompt_confirm("Execute intrusive Exploit phase as part of pipeline?", default=False)
        if include_exploit:
            set_intrusive_allowed(True)
        log("Pipeline started")
        run_pipeline(clean_target, include_exploit=include_exploit)


def main():
    try:
        init_db()
        clear_terminal()
        show_banner()

        mode = prompt_select(
            "Select Mode",
            choices=[
                "Beginner Mode",
                "Advanced Console",
                "Exit"
            ]
        )

        if mode == "Advanced Console":
            start_console()

        elif mode == "Beginner Mode":
            run_beginner_mode()

        elif mode == "Exit":
            print("Goodbye.")
            sys.exit(0)

    except (KeyboardInterrupt, EOFError):
        print("\nExiting Cyber Framework.")
        sys.exit(0)


if __name__ == "__main__":
    main()