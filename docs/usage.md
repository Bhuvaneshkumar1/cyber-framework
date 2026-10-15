# 📖 Cyber Framework Usage Guide

This guide details how to operate **Cyber Framework** across both Beginner Mode and Advanced Console Mode, configure target scope policies, execute multi-stage workflows, visualize attack graphs, and export assessment reports.

---

# ▶️ Starting the Framework

Launch the application from the repository root:

```bash
python main.py
```

Upon launching, choose between two user experience modes:
```text
Select Mode:
1. Beginner Mode
2. Advanced Console
```

---

# 🟢 Beginner Mode (Guided Workflow)

Beginner Mode provides a simplified, menu-driven interface suitable for straightforward assessments and interactive walkthroughs:

```text
[?] Select Mode: Beginner Mode
[?] Enter target domain or IP: 127.0.0.1
[?] Select operation:
  > Recon
    Scan
    Web Scan
    Exploit (Requires Confirmation)
    Attack Chain
    Full Pipeline
```

When an operation completes, results and findings are automatically stored in the SQLite database and session history.

---

# 💻 Advanced Console Mode (Interactive CLI)

Advanced Console Mode provides an interactive shell inspired by frameworks like Metasploit, complete with TAB completion, command history, and context-aware prompts:

```text
cyber>
```

### Complete Console Command Reference

| Command | Arguments | Purpose | Example |
|---|---|---|---|
| `help`, `?` | None | Display the list of supported CLI commands | `cyber> help` |
| `show modules` | None | List all discovered security modules | `cyber> show modules` |
| `show options` | None | Display active target, current module, and safety status | `cyber> show options` |
| `show info` | `[module]` | Display tool information and typical command syntax | `cyber> show info scan` |
| `show graph` | None | Display the attack surface relationship graph | `cyber> show graph` |
| `show scans` | None | View persistent scan findings stored in the database | `cyber> show scans` |
| `use` | `<module>` | Switch active context to a module | `cyber> use scan` |
| `set target` | `<target>` | Set and validate the target domain, IP, CIDR, or URL | `cyber> set target 127.0.0.1` |
| `set intrusive` | `<true\|false>` | Explicitly authorize or forbid intrusive actions | `cyber> set intrusive true` |
| `run` | None | Execute the currently selected module | `cyber(scan)> run` |
| `run pipeline` | `[--exploit]` | Execute the multi-stage security pipeline | `cyber> run pipeline` |
| `run attack_chain` | `[--exploit]` | Execute the automated multi-phase attack chain | `cyber> run attack_chain` |
| `report` | `[txt\|json\|html]` | Export assessment findings to a formatted report | `cyber> report html` |
| `man` | `<module>` | Display terminal manual page for a module | `cyber> man scan` |
| `back` | None | Return to global prompt from a module context | `cyber(scan)> back` |
| `clear` | None | Clear the terminal display | `cyber> clear` |
| `exit`, `quit` | None | Safely shutdown background tasks and exit | `cyber> exit` |

---

# 🎯 Target Configuration and Scope

Before executing any module, a target must be defined:

```text
cyber> set target 127.0.0.1
[+] Target set to: 127.0.0.1
```

### Input Validation
The target validator enforces:
- Proper IPv4 (`192.168.1.1`), IPv6 (`::1`), CIDR (`10.0.0.0/24`), hostnames (`scanme.nmap.org`), or URLs (`http://localhost:8080`).
- Strict rejection of dangerous shell characters (`;`, `&`, `|`, `` ` ``, `$`, `<`, `>`, `\`).
- Immediate rejection of parameter injection (leading `-` or `/`).

### Scope Policy
If `scope.enforce_scope` is enabled in `config.json`, the framework will verify that the target is listed in `allowed_targets`. To test targets outside the default loopback scope, update `config.json`:
```json
{
  "scope": {
    "enforce_scope": true,
    "allowed_targets": [
      "127.0.0.1",
      "localhost",
      "192.168.1.0/24",
      "authorized-lab.local"
    ]
  }
}
```

---

# 🛡 Safe Execution & Intrusive Opt-in

By default, destructive or intrusive vulnerability verification (such as SQL injection exploitation via `modules/exploit.py`) is blocked.

Attempting to run `exploit` without authorization:
```text
cyber> use exploit
cyber(exploit)> run
[-] Intrusive actions are disabled. Use 'set intrusive true' to authorize exploitation.
```

To authorize intrusive testing for the current session:
```text
cyber(exploit)> set intrusive true
[+] Intrusive actions authorized for this session.
cyber(exploit)> run
```

---

# ⚔️ Multi-Stage Workflows

### Automated Attack Chain (`run attack_chain`)
Executes a sequential penetration testing progression:
1. **Reconnaissance**: Subdomain enumeration and DNS discovery.
2. **Network Scanning**: Open port and service detection.
3. **Web Assessment**: Web vulnerability inspection and security headers.
4. **Exploitation**: Strictly skipped by default unless `--exploit` is passed and intrusive mode is authorized.

```text
cyber> set target 127.0.0.1
cyber> run attack_chain
```

### Assessment Pipeline (`run pipeline`)
Runs the end-to-end multi-module pipeline, automatically recording stage results in `data/results.json` and saving open ports to the SQLite database.

---

# 📊 Visualizing Results & Attack Graphs

### Attack Graph (`show graph`)
Renders a structured tree connecting target hosts to discovered open ports and detected services:

```text
cyber> show graph
Target: 127.0.0.1
  ├── Port: 22/tcp (ssh)
  ├── Port: 80/tcp (http)
  └── Port: 443/tcp (https)
```

### Stored Database Scans (`show scans`)
Displays historical scan records saved in the SQLite database (`cyber_framework.db`):

```text
cyber> show scans
Target: 127.0.0.1 | Port: 80 | Service: http | Detected: 2026-10-15 12:00:00
```

---

# 📋 Exporting Assessment Reports

Export findings to disk in multiple formats:

```text
cyber> report html
[+] HTML report generated successfully: reports/report_127.0.0.1_20261015.html

cyber> report json
[+] JSON report generated successfully: reports/report_127.0.0.1_20261015.json

cyber> report txt
[+] Text report generated successfully: reports/report_127.0.0.1_20261015.txt
```

Generated HTML reports include responsive CSS styling, summary statistics, and vulnerability tables with automated HTML escaping to protect against XSS.

---

# 🧩 Adding Custom Modules

To add a new capability to Cyber Framework:

1. Create a Python file inside `modules/` (e.g., `modules/ssl_check.py`).
2. Implement the standard `run(target)` function:

```python
from core.utils import ModuleResult, validate_target, is_target_in_scope

def run(target: str) -> ModuleResult:
    # 1. Validate target
    valid, clean_target = validate_target(target)
    if not valid:
        return ModuleResult("ssl_check", target, status="error", errors=[f"Invalid target: {clean_target}"])

    # 2. Scope verification
    in_scope, reason = is_target_in_scope(clean_target)
    if not in_scope:
        return ModuleResult("ssl_check", clean_target, status="error", errors=[f"Target out of scope: {reason}"])

    # 3. Perform inspection
    findings = [{"issue": "TLS 1.0 enabled", "severity": "medium"}]
    return ModuleResult("ssl_check", clean_target, status="success", findings=findings)
```

3. Add a corresponding manual page `man/ssl_check.man`.
4. Launch the framework: `show modules` will automatically discover and register your new module.
