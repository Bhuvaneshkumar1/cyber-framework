# 🏗 Cyber Framework Architecture

Cyber Framework is designed with a **modular and extensible architecture** that separates the core engine from security modules.

This allows new modules to be added without modifying the core framework.

---

# 🧠 Architecture Overview

The framework is divided into four main layers:

```

User Interface
↓
Command Console
↓
Core Framework Engine
↓
Security Modules

```

---

# 🔄 Execution Flow

Typical framework execution flow:

```

User Input
↓
Console Interface
↓
Command Parser
↓
Module Selection
↓
Module Execution
↓
Results + Intelligence Analysis
↓
Attack Graph Generation

```
---

# 🧩 Core Components

All core logic is located inside the `core/` directory.

```

core/

```

| File | Purpose |
|-----|--------|
| console.py | Interactive CLI console |
| command_parser.py | Parses user commands |
| module_loader.py | Automatic module discovery |
| attack_chain.py | Automated multi-stage attack pipeline |
| progress_engine.py | Displays real-time scan progress |
| session_manager.py | Tracks active module and target |
| intelligence_engine.py | Analyzes scan results |
| attack_graph.py | Generates attack path graphs |
| database.py | Stores scan results in SQLite |
| scheduler.py | Handles scheduled scans |
| distributed_controller.py | Supports distributed scanning |

---

# 🧱 Module System

Security modules are stored in:

```

modules/

```

Each module represents a **security capability**.

Modules must implement:

```

def run(target)

```

Example modules:

| Module | Description |
|------|-------------|
| recon | Domain reconnaissance |
| scan | Network port scanning |
| web_scan | Web vulnerability scanning |
| exploit | Exploitation stage |
| discovery | Network host discovery |
| enumeration | Target enumeration |
| intelligence | Target information gathering |

---

# 🔍 Automatic Module Discovery

The framework automatically loads modules from the `modules/` directory.

This means new modules can be added simply by placing them in the folder.

Example:

```

modules/
new_module.py

```

After restarting the framework:

```

cyber> show modules

```

The module becomes available automatically.

---

# ⚔️ Attack Chain Engine

The **Attack Chain Engine** automates multi-stage penetration testing.

Execution pipeline:

```

Recon
↓
Scan
↓
Web Scan
↓
Exploit

```

This simulates how real penetration testers move through attack phases.

---

# ⌨️ Console System

Cyber Framework provides a powerful CLI console.

Features include:

- TAB command completion
- Syntax highlighted commands
- Persistent command history
- Dynamic module prompts

Example prompt:

```

cyber(recon)>

```

Example commands:

```

cyber> show modules
cyber> use recon
cyber(recon)> set target example.com
cyber(recon)> run

```

---

# 🧠 Intelligence Engine

After scanning, the Intelligence Engine analyzes results.

Example analysis:

```

Port 22 → SSH detected → possible brute force attack
Port 80 → HTTP server detected → web attack surface

```

This helps prioritize attack paths.

---

# 📊 Attack Graph Engine

The framework generates a graph representing attack paths.

Example graph:

```

Target
↓
Open Port 80
↓
Web Server
↓
Possible Exploit

```

The attack graph helps visualize possible attack routes.

---

# 💾 Data Storage

Persistent data is stored inside the `data/` directory.

```

data/

```

| File | Purpose |
|----|--------|
| scan.db | SQLite scan database |
| command_history.txt | Console command history |

---

# ⏱ Scan Scheduler

The scheduler allows automated scans at defined intervals.

Example concept:

```

Scan example.com every 1 hour

```

This enables continuous security monitoring.

---

# 🌍 Distributed Scanning

Cyber Framework supports distributed scanning across multiple nodes.

Architecture:

```

Controller Node
↓
Worker Node
↓
Worker Node

```

This allows scanning large networks faster.

---

# 🧑‍💻 Extending the Framework

To create a new module:

1️⃣ Create a new file inside `modules/`

```

modules/my_module.py

```

2️⃣ Implement:

```

def run(target):
print("Running module on", target)

```

3️⃣ Restart framework.

Module will be automatically available.

---

# 🎯 Design Goals

Cyber Framework was designed with the following goals:

- Modular architecture
- Easy extensibility
- Professional CLI experience
- Automated attack workflows
- Educational penetration testing framework
