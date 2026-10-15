import socket
from core.os_detection import get_os
from core.tool_detection import tool_exists
from core.logger import log
from core.utils import validate_target, safe_run_subprocess, is_target_in_scope, ModuleResult
from core.session_manager import is_target_authorized
from rich import print


def run(target: str | None) -> ModuleResult:
    """
    Target intelligence gathering module.
    Gathers factual domain registration, DNS records, and ICMP connectivity data.
    Maintains strict adherence to evidence-based reporting without false vulnerability claims.
    """
    module_name = "intelligence"
    tool_name = "multi_osint"

    if not target:
        msg = "Target is required for intelligence gathering."
        print(f"[red]Error: {msg}[/red]")
        return ModuleResult(
            status="error",
            module=module_name,
            target=None,
            tool=tool_name,
            message=msg,
            error="missing_target"
        )

    valid, clean_target = validate_target(target)
    if not valid:
        msg = f"Invalid target '{target}': {clean_target}"
        print(f"[red]Error: {msg}[/red]")
        return ModuleResult(
            status="error",
            module=module_name,
            target=target,
            tool=tool_name,
            message=msg,
            error="invalid_target"
        )

    # Scope authorization check
    if not is_target_authorized(clean_target):
        in_scope, scope_msg = is_target_in_scope(clean_target)
        if not in_scope:
            print(f"[red]Security Policy Violation: {scope_msg}[/red]")
            return ModuleResult(
                status="unauthorized",
                module=module_name,
                target=clean_target,
                tool=tool_name,
                message=scope_msg,
                error="out_of_scope"
            )

    log(f"Intelligence gathering started for {clean_target}")
    system = get_os()

    print(f"[bold cyan]Gathering target intelligence for:[/bold cyan] {clean_target}")
    findings = []
    output_lines = [f"Intelligence Report for {clean_target}:"]

    # 1. Empirical DNS Resolution (Always verified first via native socket)
    try:
        resolved_addrs = socket.getaddrinfo(clean_target, None)
        unique_ips = sorted(list(set(r[4][0] for r in resolved_addrs if r and r[4])))
        findings.append({
            "category": "dns",
            "nature": "observed",
            "details": f"Target resolves to IP(s): {', '.join(unique_ips)}"
        })
        output_lines.append(f" - [Observed DNS] IP Address(es): {', '.join(unique_ips)}")
    except socket.gaierror as e:
        findings.append({
            "category": "dns",
            "nature": "observed",
            "details": f"DNS hostname resolution failed: {e}"
        })
        output_lines.append(f" - [Observed DNS] Resolution failed: {e}")

    # 2. Whois Registration Lookup (if tool exists)
    if tool_exists("whois"):
        output_lines.append(" - [OSINT Query] Querying whois database...")
        res = safe_run_subprocess(["whois", clean_target], timeout=15)
        if res and res.stdout:
            raw_whois = res.stdout
            registrar_match = None
            for line in raw_whois.splitlines():
                if "Registrar:" in line or "registrar:" in line:
                    registrar_match = line.strip()
                    break

            findings.append({
                "category": "whois",
                "nature": "observed",
                "details": registrar_match or "Whois data retrieved successfully"
            })
            output_lines.append(f"   {registrar_match or 'Whois record retrieved'}")
        else:
            output_lines.append("   Whois lookup produced no output or timed out.")
    else:
        output_lines.append(" - [Notice] 'whois' tool not installed on system; skipping registrar discovery.")

    # 3. DNS Lookup utility (nslookup)
    if tool_exists("nslookup"):
        res = safe_run_subprocess(["nslookup", clean_target], timeout=10)
        if res and res.stdout:
            findings.append({
                "category": "nslookup",
                "nature": "observed",
                "details": "Authoritative nameserver answers obtained"
            })

    # 4. ICMP Connectivity Check (Ping)
    if tool_exists("ping"):
        ping_args = ["ping", "-n", "2", clean_target] if system == "windows" else ["ping", "-c", "2", clean_target]
        res = safe_run_subprocess(ping_args, timeout=10)
        if res and res.stdout and ("Reply from" in res.stdout or "bytes from" in res.stdout):
            findings.append({
                "category": "connectivity",
                "nature": "observed",
                "details": "Target responded to ICMP echo requests"
            })
            output_lines.append(" - [Observed Network] ICMP Echo reply received (Host is active).")
        else:
            findings.append({
                "category": "connectivity",
                "nature": "observed",
                "details": "No ICMP Echo reply received (Host may drop ICMP or be offline)"
            })
            output_lines.append(" - [Observed Network] No ICMP Echo reply (Host may filter ICMP traffic).")

    raw_output = "\n".join(output_lines)
    print(raw_output)

    log(f"Intelligence gathering completed for {clean_target}. Observations recorded: {len(findings)}")
    return ModuleResult(
        status="success",
        module=module_name,
        target=clean_target,
        tool=tool_name,
        findings=findings,
        raw_output=raw_output,
        message=f"Recorded {len(findings)} verified intelligence observations."
    )