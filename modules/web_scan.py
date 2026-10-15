import urllib.request
import urllib.error
from urllib.parse import urlparse
from core.tool_detection import tool_exists
from core.utils import validate_target, safe_run_subprocess, is_target_in_scope, ModuleResult
from core.session_manager import is_target_authorized
from core.logger import log
from rich import print

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


def inspect_http_headers(url: str, timeout: float = 8.0) -> tuple[bool, list[dict], str]:
    """
    Lightweight, unprivileged HTTP header inspector.
    Inspects server banners, redirects, and missing defensive security headers without external tools.
    """
    findings = []
    output_lines = [f"HTTP Inspection Results for {url}:"]

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "CyberFramework-Inspector/1.0"},
        method="GET"
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status_code = response.getcode()
            response_url = response.geturl()
            headers = dict(response.info())

            output_lines.append(f" - Status Code: {status_code}")
            findings.append({
                "scanner": "builtin_http_inspector",
                "type": "http_status",
                "details": f"Target responded with HTTP {status_code}"
            })

            # Check if redirected to different domain/host
            if urlparse(response_url).hostname != urlparse(url).hostname:
                output_lines.append(f" - Redirected to: {response_url}")
                findings.append({
                    "scanner": "builtin_http_inspector",
                    "type": "redirect_cross_origin",
                    "details": f"Redirected to external host: {response_url}"
                })

            # Check server banner
            server_header = headers.get("Server") or headers.get("server")
            if server_header:
                output_lines.append(f" - Server Banner: {server_header}")
                findings.append({
                    "scanner": "builtin_http_inspector",
                    "type": "server_banner",
                    "details": f"Server: {server_header}"
                })

            # Check technology headers
            powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
            if powered_by:
                output_lines.append(f" - Technology: {powered_by}")
                findings.append({
                    "scanner": "builtin_http_inspector",
                    "type": "technology_header",
                    "details": f"X-Powered-By: {powered_by}"
                })

            # Check for missing defensive headers
            missing_headers = [h for h in SECURITY_HEADERS if h.lower() not in [k.lower() for k in headers.keys()]]
            for missing in missing_headers:
                findings.append({
                    "scanner": "builtin_http_inspector",
                    "type": "missing_security_header",
                    "details": f"Missing defensive header: {missing}"
                })
            if missing_headers:
                output_lines.append(f" - Missing Security Headers ({len(missing_headers)}): {', '.join(missing_headers)}")

        return True, findings, "\n".join(output_lines)
    except urllib.error.HTTPError as http_err:
        output_lines.append(f" - HTTP Error: {http_err.code} {http_err.reason}")
        findings.append({
            "scanner": "builtin_http_inspector",
            "type": "http_error",
            "details": f"HTTP {http_err.code} {http_err.reason}"
        })
        return True, findings, "\n".join(output_lines)
    except Exception as e:
        output_lines.append(f" - Connection failed: {e}")
        return False, findings, "\n".join(output_lines)


def run(target: str | None) -> ModuleResult:
    """
    Web server vulnerability scanning module.
    Runs Nikto if available, or falls back to native HTTP header inspection.
    Enforces URL validation, destination scope checks, and explicit finding attribution.
    """
    module_name = "web_scan"
    tool_name = "nikto" if tool_exists("nikto") else "builtin_http_inspector"

    if not target:
        msg = "Target is required for web scanning."
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

    # Construct safe URL with explicit scheme
    if "://" in clean_target:
        target_url = clean_target
    else:
        target_url = f"http://{clean_target}"

    findings = []
    raw_output = ""
    used_tool = None

    # Strategy 1: Nikto CLI tool (if available)
    if tool_exists("nikto"):
        used_tool = "nikto"
        print(f"[bold cyan]Running web vulnerability scan against:[/bold cyan] {target_url} [dim](via nikto)[/dim]")
        log(f"Web scan started for {target_url} using nikto")

        # Controlled tuning (avoids destructive test suites)
        result = safe_run_subprocess(["nikto", "-h", target_url, "-Tuning", "123b"], timeout=120)

        if result and result.stdout:
            raw_output = result.stdout
            print(raw_output)

            for line in raw_output.splitlines():
                if line.startswith("+ "):
                    findings.append({
                        "scanner": "nikto",
                        "type": "nikto_item",
                        "details": line[2:].strip()
                    })

            log(f"Nikto scan completed for {target_url}. Findings: {len(findings)}")
            return ModuleResult(
                status="success",
                module=module_name,
                target=clean_target,
                tool=used_tool,
                findings=findings,
                raw_output=raw_output,
                message=f"Discovered {len(findings)} web items via nikto."
            )
        elif result is None:
            msg = "Nikto scan timed out or failed to execute."
            return ModuleResult(
                status="timeout",
                module=module_name,
                target=clean_target,
                tool=used_tool,
                message=msg,
                error="timeout_or_exec_failure"
            )

    # Strategy 2: Built-in HTTP Header and Defensive Configuration Inspector
    used_tool = "builtin_http_inspector"
    print(f"[bold cyan]Running web inspection on:[/bold cyan] {target_url} [dim](via builtin http inspector)[/dim]")
    log(f"Web inspection initiated for {target_url} using builtin inspector")

    success, findings, output_text = inspect_http_headers(target_url, timeout=10.0)
    print(output_text)

    log(f"Web inspection completed for {target_url}. Findings: {len(findings)}")
    status = "success" if success else "error"
    return ModuleResult(
        status=status,
        module=module_name,
        target=clean_target,
        tool=used_tool,
        findings=findings,
        raw_output=output_text,
        message=f"Inspection complete with {len(findings)} findings.",
        error=None if success else "Connection or inspection failed"
    )