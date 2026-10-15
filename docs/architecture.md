# 🏗 Cyber Framework Architecture

Cyber Framework is designed with a **modular, multi-layer architecture** that strictly separates interface presentation, command parsing, session state, safety policy, and security execution modules.

This architecture enables developers to add new security modules without modifying core framework code, while guaranteeing that all modules benefit from centralized target validation, scope control, logging, and data persistence.

---

# 🧠 Architecture Overview

The framework is structured into four primary layers:

```text
+-----------------------------------------------------------+
|                  1. User Interface Layer                  |
|          Beginner Menu Mode   |   Advanced Console        |
+-----------------------------+-----------------------------+
                              |
                              v
+-----------------------------------------------------------+
|                 2. Command & Session Layer                |
|    Command Parser   |   Session Manager   |   Console Lexer|
+-----------------------------+-----------------------------+
                              |
                              v
+-----------------------------------------------------------+
|                   3. Core Security Engine                 |
|   Target Validation & Scope Policy  |  Safe Subprocess    |
|   Attack Chain Engine               |  Pipeline Engine    |
|   Intelligence Engine               |  Attack Graph Engine|
|   Progress & Task Scheduler         |  SQLite DB & Reports|
+-----------------------------+-----------------------------+
                              |
                              v
+-----------------------------------------------------------+
|                     4. Security Modules                   |
|     recon  |  scan  |  web_scan  |  exploit  |  intelligence|
+-----------------------------------------------------------+
```

---

# 🔄 End-to-End Execution Flow

A typical operation traverses the framework as follows:

```text
User Command / Menu Selection
          │
          ▼
Prompt Toolkit Console (`core/console.py` / `core/advanced_console.py`)
          │
          ▼
Command Dispatcher (`core/command_parser.py`)
          │
          ├───────────────────────────────┐
          ▼                               ▼
Session & Target Update             Module Selection / Workflow Run
(`core/session_manager.py`)                 │
          │                               ▼
          │                     Target & Scope Authorization Check
          │                     (`core/utils.py` -> `is_target_in_scope`)
          │                               │
          │                               ▼
          │                     Intrusive Safety Gate
          │                     (Blocks exploitation if unconfirmed)
          │                               │
          │                               ▼
          └────────────────────► Module Execution (`modules/<module>.py`)
                                          │
                                          ▼
                                Subprocess or Native Fallback
                                (`core/utils.py` -> `safe_run_subprocess`)
                                          │
                                          ▼
                                Standardized `ModuleResult`
                                          │
                        ┌─────────────────┴─────────────────┐
                        ▼                                   ▼
          Persistent Storage Layer                Intelligence & Graphs
      SQLite (`cyber_framework.db`)         Correlation (`core/intelligence_engine.py`)
      JSON (`data/results.json`)            Graph Nodes (`core/attack_graph.py`)
                        │                                   │
                        └─────────────────┬─────────────────┘
                                          ▼
                              Report Generation & Output
                              (`core/report.py` & `core/output.py`)
```

---

# 🧩 Core Components (`core/`)

| Component | Responsibility |
|---|---|
| `command_parser.py` | Dispatches CLI commands (`use`, `set`, `run`, `show`, `report`, `man`) with input validation. |
| `session_manager.py` | Tracks active target, current module, target staleness, explicit authorization, and intrusive opt-in status. |
| `utils.py` | Central security utilities: input sanitization (`validate_target`), scope policy (`is_target_in_scope`), safe argument-vector subprocess execution (`safe_run_subprocess`), and atomic JSON file I/O. |
| `database.py` | SQLite persistence layer with transaction management (`get_db_connection`), automatic schema migrations, and scan record queries. |
| `attack_chain.py` | Automated multi-phase execution: `Recon` -> `Scan` -> `Web Scan` -> `(Optional Exploit)`. |
| `pipeline.py` | Structured multi-stage pipeline runner with stage result recording and database saving. |
| `attack_graph.py` | Structural attack surface mapping: builds verified Target -> Port -> Service relationships with Rich tree rendering. |
| `intelligence_engine.py` | Correlation engine distinguishing empirical DNS/network facts from protocol hypotheses. |
| `report.py` | Exports assessment findings to formatted Text, JSON, and XSS-sanitized HTML reports. |
| `logger.py` | File logger (`scan.log`) with automatic redaction of passwords, tokens, and basic authentication secrets. |
| `module_loader.py` | Dynamically discovers and imports Python modules from `modules/` verifying the `run(target)` contract. |
| `man_viewer.py` | Displays formatted manual pages from `man/` with path traversal protection. |
| `module_info.py` | Central metadata dictionary detailing underlying CLI tools, sample commands, and capabilities. |
| `progress_engine.py` | Real-time honest execution feedback using Rich status spinners (no artificial sleep delays). |
| `scheduler.py` | Background recurring scan scheduler utilizing `apscheduler` with graceful shutdown. |
| `tool_detection.py` | System PATH detector for external binaries (`nmap`, `theHarvester`, `nikto`, `sqlmap`) with install guidance. |
| `os_detection.py` | Operating system environment and administrative privilege (`is_elevated`) detector. |
| `output.py` | Unified terminal output formatting and panels with graceful fallback if Rich is unavailable. |
| `syntax_highlighter.py` | Lexer for Prompt Toolkit CLI providing real-time command, keyword, and parameter styling. |
| `distributed_controller.py` | **Experimental**: Proof-of-concept socket listener for distributed scanning nodes (disabled by default). |

---

# 🧱 Security Module System

All security modules reside in `modules/` and must adhere to the standard interface contract:

```python
def run(target: str) -> ModuleResult:
    """Execute the security module against a validated target."""
    ...
```

### Module Result Contract
Every module returns a structured `ModuleResult` dictionary:
```python
{
    "module": "scan",
    "target": "127.0.0.1",
    "status": "success",          # "success", "error", or "skipped"
    "timestamp": "2026-10-15T12:00:00",
    "findings": [...],            # Discovered ports, headers, or records
    "errors": [],                 # Non-fatal error messages or tool notices
    "details": {...}              # Raw output and execution metadata
}
```

Because `ModuleResult` implements `__bool__` based on `status == "success"`, legacy callers expecting boolean return values continue to function seamlessly.

### Implemented Modules

| Module | Primary External Tool | Automatic Fallback Mechanism | Safety Classification |
|---|---|---|---|
| `recon` | `theHarvester` | Python socket DNS resolver & reverse lookup | Passive (Non-destructive) |
| `scan` | `nmap` (`-sT`) | Pure-Python multi-threaded TCP socket scanner | Active (Unprivileged Connect) |
| `web_scan` | `nikto` | Native HTTP security header inspector | Active (HTTP Audit) |
| `exploit` | `sqlmap` | None (Tool required) | **Intrusive (Explicit Opt-in Required)** |
| `intelligence` | Native Engine | Built-in empirical heuristics | Passive / Analysis |

---

# 🛡 Central Defensive Controls

### 1. Scope & Target Policy
All commands setting a target or running a workflow pass through `validate_target` and `is_target_in_scope` in `core/utils.py`. The framework rejects:
- Null, empty, or whitespace-only inputs.
- Shell metacharacters (`&`, `;`, `|`, `` ` ``, `$`, `<`, `>`, `\`, `\r`, `\n`).
- Option injection attempts (targets beginning with `-` or `/`).
- Out-of-scope targets when `enforce_scope: true` in `config.json`.

### 2. Intrusive Action Gating
Potentially destructive or intrusive testing (e.g., SQL injection payload fuzzing via `exploit.py`) is blocked by default. It requires:
1. `config.json` having `"allow_intrusive_actions": true` OR the interactive console setting `set intrusive true`.
2. Explicit target authorization.

### 3. Safe Subprocess Execution
All external process calls invoke `safe_run_subprocess` with:
- An explicit argument vector list (`List[str]`), strictly avoiding shell string concatenation.
- Explicit timeouts (`subprocess_timeout_seconds`).
- Output capture and decoding with error recovery.

### 4. Backward-Compatible SQLite Storage
The SQLite database (`cyber_framework.db`) uses `PRAGMA table_info` schema inspection at startup. Pre-existing databases are automatically migrated to add the `timestamp` column without dropping tables or losing historical data.
