import json
import html
import datetime
from pathlib import Path
from core.utils import PROJECT_ROOT

DEFAULT_REPORT_DIR = PROJECT_ROOT / "data" / "reports"


def get_reports_dir() -> Path:
    DEFAULT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_REPORT_DIR


def generate_report(
    target: str,
    findings: list | dict,
    output_format: str = "txt",
    output_dir: Path | str | None = None,
    metadata: dict | None = None
) -> tuple[bool, str]:
    """
    Generate an accurate, structured penetration testing report.
    Supported formats: 'txt', 'json', 'html'.
    Properly escapes all untrusted user/target data to prevent HTML injection.
    """
    if not target or not isinstance(target, str):
        return False, "Target name is required for report generation."

    format_clean = (output_format or "txt").lower().strip()
    if format_clean not in ("txt", "json", "html"):
        return False, f"Unsupported report format: '{output_format}'. Supported formats: 'txt', 'json', 'html'."

    out_dir = Path(output_dir) if output_dir else get_reports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target_filename = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)
    filename = f"report_{clean_target_filename}_{timestamp}.{format_clean}"
    file_path = out_dir / filename

    report_metadata = {
        "target": target,
        "generated_at": datetime.datetime.now().isoformat(),
        "total_items": len(findings) if isinstance(findings, list) else len(findings.keys()),
        **(metadata or {})
    }

    try:
        if format_clean == "json":
            payload = {
                "report_metadata": report_metadata,
                "findings": findings
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)

        elif format_clean == "html":
            safe_target = html.escape(target)
            safe_gen_time = html.escape(report_metadata["generated_at"])

            html_lines = [
                "<!DOCTYPE html>",
                "<html lang=\"en\">",
                "<head>",
                "  <meta charset=\"UTF-8\">",
                "  <title>Cyber Framework Assessment Report - " + safe_target + "</title>",
                "  <style>",
                "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; margin: 0; }",
                "    .container { max-width: 900px; margin: auto; background: #161b22; padding: 25px; border-radius: 8px; border: 1px solid #30363d; }",
                "    h1 { color: #58a6ff; margin-top: 0; border-bottom: 1px solid #30363d; padding-bottom: 10px; }",
                "    .meta { color: #8b949e; font-size: 0.9em; margin-bottom: 20px; }",
                "    table { width: 100%; border-collapse: collapse; margin-top: 15px; }",
                "    th, td { border: 1px solid #30363d; padding: 10px; text-align: left; }",
                "    th { background: #21262d; color: #58a6ff; }",
                "    tr:nth-child(even) { background: #0d1117; }",
                "    .badge { padding: 3px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; background: #238636; color: #fff; }",
                "    pre { background: #0d1117; padding: 10px; border-radius: 5px; overflow-x: auto; color: #7ee787; }",
                "  </style>",
                "</head>",
                "<body>",
                "  <div class=\"container\">",
                f"    <h1>Cyber Security Assessment Report</h1>",
                f"    <div class=\"meta\"><strong>Target:</strong> {safe_target} | <strong>Generated:</strong> {safe_gen_time}</div>",
                "    <h2>Findings & Execution Summary</h2>"
            ]

            if isinstance(findings, list):
                html_lines.append("    <table>")
                html_lines.append("      <thead><tr><th>#</th><th>Details</th></tr></thead>")
                html_lines.append("      <tbody>")
                for idx, item in enumerate(findings, 1):
                    safe_item = html.escape(json.dumps(item, indent=2) if isinstance(item, (dict, list)) else str(item))
                    html_lines.append(f"        <tr><td>{idx}</td><td><pre>{safe_item}</pre></td></tr>")
                html_lines.append("      </tbody>")
                html_lines.append("    </table>")
            elif isinstance(findings, dict):
                html_lines.append("    <table>")
                html_lines.append("      <thead><tr><th>Stage / Category</th><th>Summary</th></tr></thead>")
                html_lines.append("      <tbody>")
                for k, v in findings.items():
                    safe_key = html.escape(str(k))
                    safe_val = html.escape(json.dumps(v, indent=2) if isinstance(v, (dict, list)) else str(v))
                    html_lines.append(f"        <tr><td><strong>{safe_key}</strong></td><td><pre>{safe_val}</pre></td></tr>")
                html_lines.append("      </tbody>")
                html_lines.append("    </table>")

            html_lines.extend([
                "  </div>",
                "</body>",
                "</html>"
            ])

            with open(file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(html_lines))

        else:
            # Plain text
            txt_lines = [
                "=" * 60,
                f"CYBER SECURITY ASSESSMENT REPORT: {target}",
                f"Generated at: {report_metadata['generated_at']}",
                "=" * 60,
                "",
                "FINDINGS SUMMARY:",
                "-" * 60,
            ]
            if isinstance(findings, list):
                for i, item in enumerate(findings, 1):
                    txt_lines.append(f"[{i}] {json.dumps(item) if isinstance(item, (dict, list)) else str(item)}")
            elif isinstance(findings, dict):
                for k, v in findings.items():
                    txt_lines.append(f"[{k}]: {json.dumps(v, indent=2) if isinstance(v, (dict, list)) else str(v)}")
            txt_lines.extend(["", "=" * 60, "END OF REPORT", "=" * 60])

            with open(file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(txt_lines))

        return True, str(file_path)
    except Exception as e:
        return False, f"Failed to write report file: {e}"