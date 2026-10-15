import datetime
from modules import recon, scan, web_scan, exploit, intelligence
from core.utils import validate_target, is_target_in_scope, save_json_file, load_json_file, PROJECT_ROOT
from core.session_manager import is_target_authorized, is_intrusive_allowed
from core.logger import log
from rich import print


def run_pipeline(target: str | None, include_exploit: bool = False) -> dict:
    """
    Unified multi-stage penetration testing pipeline.
    Executes Recon -> Scan -> Web Scan -> Intelligence -> (Optional) Exploit sequentially.
    Preserves stage results, propagates errors, and records output to data/results.json.
    """
    if not target:
        msg = "Target is required for pipeline execution."
        print(f"[red]Error: {msg}[/red]")
        return {"status": "error", "message": msg, "stages": {}}

    valid, clean_target = validate_target(target)
    if not valid:
        msg = f"Invalid target '{target}': {clean_target}"
        print(f"[red]Error: {msg}[/red]")
        return {"status": "error", "message": msg, "stages": {}}

    if not is_target_authorized(clean_target):
        in_scope, scope_msg = is_target_in_scope(clean_target)
        if not in_scope:
            print(f"[red]Security Policy Violation: {scope_msg}[/red]")
            return {"status": "unauthorized", "message": scope_msg, "stages": {}}

    print(f"\n[bold green]===== Starting Security Pipeline for {clean_target} =====[/bold green]\n")
    log(f"Pipeline started for {clean_target}")

    stages = {}
    timestamp = datetime.datetime.now().isoformat()

    # Stage 1: Reconnaissance
    print("[bold cyan]>>> Stage 1: Reconnaissance[/bold cyan]")
    recon_res = recon.run(clean_target)
    stages["recon"] = recon_res

    # Stage 2: Port & Service Scanning
    print("\n[bold cyan]>>> Stage 2: Network Port Scanning[/bold cyan]")
    scan_res = scan.run(clean_target)
    stages["scan"] = scan_res

    # Stage 3: Web Vulnerability Scanning
    print("\n[bold cyan]>>> Stage 3: Web Server Scanning[/bold cyan]")
    web_res = web_scan.run(clean_target)
    stages["web_scan"] = web_res

    # Stage 4: Target Intelligence Gathering
    print("\n[bold cyan]>>> Stage 4: Target Intelligence Gathering[/bold cyan]")
    intel_res = intelligence.run(clean_target)
    stages["intelligence"] = intel_res

    # Stage 5: Optional Intrusive Exploitation
    should_exploit = include_exploit or is_intrusive_allowed()
    if should_exploit:
        print("\n[bold red]>>> Stage 5: Exploitation (Intrusive Mode Active)[/bold red]")
        exploit_res = exploit.run(clean_target)
        stages["exploit"] = exploit_res
    else:
        print("\n[yellow]>>> Stage 5: Exploit phase skipped (Intrusive actions require explicit opt-in).[/yellow]")
        stages["exploit"] = {"status": "skipped", "message": "Intrusive actions not authorized"}

    all_success = all(s.get("status") in ("success", "skipped") for s in stages.values())
    overall_status = "success" if all_success else "partial"

    pipeline_record = {
        "timestamp": timestamp,
        "target": clean_target,
        "status": overall_status,
        "stages": {k: dict(v) if isinstance(v, dict) else str(v) for k, v in stages.items()}
    }

    # Persist to data/results.json
    results_path = PROJECT_ROOT / "data" / "results.json"
    existing_results = load_json_file(results_path, default=[])
    if not isinstance(existing_results, list):
        existing_results = []
    existing_results.append(pipeline_record)
    save_json_file(results_path, existing_results)

    log(f"Pipeline completed for {clean_target} with status: {overall_status}")
    print(f"\n[bold green]===== Pipeline Finished ({overall_status.upper()}) =====[/bold green]\n")
    return pipeline_record