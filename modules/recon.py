import socket
import re
from core.output import show_output
from core.tool_detection import tool_exists
from core.utils import validate_target, safe_run_subprocess, is_target_in_scope, ModuleResult
from core.session_manager import is_target_authorized
from core.logger import log


def run(target: str | None) -> ModuleResult:
    """
    Reconnaissance module.
    Performs passive DNS and OSINT reconnaissance with target validation,
    scope verification, structured finding extraction, and tool fallbacks.
    """
    module_name = "recon"
    tool_name = "theHarvester" if tool_exists("theHarvester") else "nslookup"

    if not target:
        msg = "Target domain or IP is required for reconnaissance."
        show_output("Recon Error", msg)
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
        show_output("Recon Error", msg)
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
            show_output("Security Policy Violation", scope_msg)
            return ModuleResult(
                status="unauthorized",
                module=module_name,
                target=clean_target,
                tool=tool_name,
                message=scope_msg,
                error="out_of_scope"
            )

    log(f"Recon started for {clean_target}")
    findings = []
    raw_output = ""
    used_tool = None

    # Strategy 1: theHarvester (if available)
    if tool_exists("theHarvester"):
        used_tool = "theHarvester"
        res = safe_run_subprocess(
            ["theHarvester", "-d", clean_target, "-b", "google", "-l", "50"],
            timeout=45
        )
        if res and res.stdout:
            raw_output = res.stdout
            show_output("Recon Results (theHarvester)", raw_output)

            # Parse emails and hosts
            for line in raw_output.splitlines():
                if "@" in line and "." in line:
                    email_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", line)
                    if email_match:
                        findings.append({"type": "email", "value": email_match.group(0)})
                elif ":" in line and clean_target in line:
                    findings.append({"type": "host", "value": line.strip()})

            return ModuleResult(
                status="success",
                module=module_name,
                target=clean_target,
                tool=used_tool,
                findings=findings,
                raw_output=raw_output,
                message=f"Discovered {len(findings)} OSINT items via theHarvester."
            )

    # Strategy 2: nslookup (CLI tool)
    if tool_exists("nslookup"):
        used_tool = "nslookup"
        res = safe_run_subprocess(["nslookup", clean_target], timeout=15)
        if res and res.stdout:
            raw_output = res.stdout
            show_output("DNS Lookup (nslookup)", raw_output)

            in_answer_section = False
            for line in raw_output.splitlines():
                line_str = line.strip()
                if "Non-authoritative answer:" in line_str or "Name:" in line_str:
                    in_answer_section = True

                if "Name:" in line_str:
                    parts = line_str.split(":", 1)
                    if len(parts) > 1 and parts[1].strip():
                        findings.append({"type": "canonical_name", "value": parts[1].strip()})
                elif in_answer_section and ("Address:" in line_str or "Addresses:" in line_str):
                    parts = line_str.split(":", 1)
                    if len(parts) > 1 and parts[1].strip():
                        findings.append({"type": "dns_address", "value": parts[1].strip()})
                elif in_answer_section and line.startswith((" ", "\t")) and line_str:
                    try:
                        import ipaddress
                        ipaddress.ip_address(line_str)
                        findings.append({"type": "dns_address", "value": line_str})
                    except ValueError:
                        pass

            if findings:
                return ModuleResult(
                    status="success",
                    module=module_name,
                    target=clean_target,
                    tool=used_tool,
                    findings=findings,
                    raw_output=raw_output,
                    message=f"Resolved {len(findings)} DNS records via nslookup."
                )

    # Strategy 3: Pure Python socket DNS resolution fallback
    used_tool = "python_socket_dns"
    try:
        addr_info = socket.getaddrinfo(clean_target, None)
        ips = sorted(list(set(item[4][0] for item in addr_info if item and item[4])))

        for ip in ips:
            findings.append({"type": "dns_resolved_ip", "value": ip})

        output_text = f"Host: {clean_target}\nResolved IP addresses:\n" + "\n".join(f" - {ip}" for ip in ips)
        show_output("DNS Resolution (Native Resolver)", output_text)
        log(f"Recon completed for {clean_target} using socket DNS fallback.")

        return ModuleResult(
            status="success",
            module=module_name,
            target=clean_target,
            tool=used_tool,
            findings=findings,
            raw_output=output_text,
            message=f"Resolved {len(findings)} IP addresses via native resolver."
        )
    except socket.gaierror as dns_err:
        msg = f"DNS resolution failed for '{clean_target}': {dns_err}"
        show_output("Recon Notice", msg)
        log(msg)
        return ModuleResult(
            status="error",
            module=module_name,
            target=clean_target,
            tool=used_tool,
            findings=[],
            raw_output="",
            message=msg,
            error=str(dns_err)
        )