import socket
import re
from core.tool_detection import tool_exists
from core.intelligence_engine import analyze
from core.attack_graph import add_port
from core.database import save_port
from core.utils import validate_target, safe_run_subprocess, is_target_in_scope, ModuleResult
from core.session_manager import is_target_authorized
from core.logger import log
try:
    from rich import print
except ImportError:
    pass

# Default non-intrusive port list for native fallback scanning
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443]


def run_native_socket_scan(target_host: str, ports: list[int] = COMMON_PORTS, timeout: float = 0.5) -> list[dict]:
    """
    Lightweight, unprivileged TCP connect scanner.
    Enables safe local baseline scanning without requiring external binaries or root access.
    """
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result = s.connect_ex((target_host, port))
            if result == 0:
                open_ports.append({"port": port, "protocol": "tcp", "state": "open"})
        except Exception:
            pass
        finally:
            s.close()
    return open_ports


def run(target: str | None) -> ModuleResult:
    """
    Port and service discovery module.
    Runs non-intrusive, unprivileged scans by default with target validation,
    scope verification, intelligence correlation, and pure Python socket fallback.
    """
    module_name = "scan"
    tool_name = "nmap" if tool_exists("nmap") else "socket_scanner"

    if not target:
        msg = "Target is required for scanning."
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

    findings = []
    raw_output = ""
    used_tool = None

    # Strategy 1: Nmap with safe unprivileged connect scan flags (-sT)
    if tool_exists("nmap"):
        used_tool = "nmap"
        # Safe default: standard TCP connect scan on top 100 ports without requiring sudo
        cmd = ["nmap", "-sT", "-T3", "-Pn", "--top-ports", "100", clean_target]
        print(f"[bold cyan]Running network scan on:[/bold cyan] {clean_target} [dim](via nmap)[/dim]")
        log(f"Scan initiated for {clean_target} with command: {' '.join(cmd)}")

        result = safe_run_subprocess(cmd, timeout=90)
        if result and result.stdout:
            raw_output = result.stdout
            print(raw_output)

            port_pattern = re.compile(r"^\s*(\d+)/tcp\s+open\s+(\S+)", re.IGNORECASE)
            for line in raw_output.splitlines():
                match = port_pattern.search(line)
                if match:
                    try:
                        port = int(match.group(1))
                        service = match.group(2)
                        intel = analyze(port)

                        findings.append({
                            "port": port,
                            "protocol": "tcp",
                            "service": service,
                            "intelligence": intel
                        })

                        print(f"[bold green][INTELLIGENCE][/bold green] Port {port}: {intel}")
                        add_port(port, target=clean_target, service=service)
                        save_port(clean_target, port, service)
                    except ValueError:
                        continue

            log(f"Nmap scan completed for {clean_target}. Open ports found: {len(findings)}")
            return ModuleResult(
                status="success",
                module=module_name,
                target=clean_target,
                tool=used_tool,
                findings=findings,
                raw_output=raw_output,
                message=f"Discovered {len(findings)} open TCP ports via nmap."
            )
        elif result is None:
            msg = "Nmap scan timed out or failed to execute."
            return ModuleResult(
                status="timeout",
                module=module_name,
                target=clean_target,
                tool=used_tool,
                message=msg,
                error="timeout_or_exec_failure"
            )

    # Strategy 2: Native socket scanner fallback (works on any OS without prerequisites)
    used_tool = "socket_scanner"
    print(f"[bold cyan]Running network scan on:[/bold cyan] {clean_target} [dim](via native socket scanner)[/dim]")
    log(f"Scan initiated for {clean_target} with native socket scanner on {len(COMMON_PORTS)} ports")

    discovered = run_native_socket_scan(clean_target, COMMON_PORTS, timeout=0.6)
    output_lines = [f"Scan Results for {clean_target} (Native TCP Connect Scanner):"]

    for item in discovered:
        port = item["port"]
        intel = analyze(port)
        service = intel.get("service", "unknown")

        findings.append({
            "port": port,
            "protocol": "tcp",
            "service": service,
            "intelligence": intel
        })
        output_lines.append(f" - Port {port}/tcp open ({service})")
        print(f"[bold green][OPEN PORT][/bold green] {port}/tcp ({service}) | {intel}")
        add_port(port, target=clean_target, service=service)
        save_port(clean_target, port, service)

    raw_output = "\n".join(output_lines)
    if not discovered:
        print("[yellow]No open ports detected among scanned common ports.[/yellow]")

    log(f"Socket scan completed for {clean_target}. Open ports found: {len(findings)}")
    return ModuleResult(
        status="success",
        module=module_name,
        target=clean_target,
        tool=used_tool,
        findings=findings,
        raw_output=raw_output,
        message=f"Discovered {len(findings)} open TCP ports via native socket scanner."
    )