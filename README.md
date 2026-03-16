# 🛡️ Cyber Framework
![Cyber Framework Banner](Screenshots/banner.png)

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-green)
![License](https://img.shields.io/badge/license-MIT-brightgreen)
![Status](https://img.shields.io/badge/status-active-success)
![Maintained](https://img.shields.io/badge/maintained-yes-blue)
![GitHub stars](https://img.shields.io/github/stars/Bhuvaneshkumar1/cyber-framework?style=social)

A **modular cybersecurity CLI framework** written in Python designed for reconnaissance, scanning, vulnerability analysis, and automated attack chains.

The framework provides:

- 🟢 Beginner Mode (menu-based)
- 💻 Advanced Console Mode
- ⚔️ Automated Attack Chain Engine
- 🧠 Intelligence & attack graph generation
- ⌨️ Professional interactive console

Inspired by penetration testing frameworks such as **Metasploit**.

---

# ⭐ Why Cyber Framework

Most cybersecurity tools focus on a **single capability** such as scanning, exploitation, or reconnaissance.

Cyber Framework integrates multiple phases of a penetration testing workflow into a **single modular CLI environment**, enabling security researchers to simulate realistic attack pipelines.

Key objectives of the framework:

• Provide a **Metasploit-style learning platform**  
• Demonstrate **attack chain automation**  
• Enable **modular security tool development**  
• Provide an **interactive penetration testing console**

This project is designed for:

- Cybersecurity students
- Ethical hackers
- Security researchers
- Developers building offensive security tools


---

# 🚀 Features

### Core Framework
✅ Beginner Mode  
✅ Advanced Console Mode  
✅ Automatic Module Discovery  
✅ Automated Attack Chain Engine  
✅ Real-time Scan Progress  

### Console Experience
⌨️ TAB command auto-completion  
🧠 Syntax highlighted commands  
📜 Persistent command history  
🎯 Dynamic module prompt  

### Security Engine
🔍 Reconnaissance modules  
🌐 Network scanning modules  
🕸 Web vulnerability scanning  
⚡ Exploit phase integration  



### 🧠 Intelligence Engine

The Intelligence Engine correlates reconnaissance and scanning results to build a **structured target profile**.

Capabilities include:

• Domain information analysis  
• DNS record intelligence  
• IP reputation correlation  
• Attack surface mapping  

The intelligence module can be extended to integrate with:

- Threat intelligence feeds
- OSINT databases
- Vulnerability databases


### Advanced Capabilities
📊 Attack Graph Generation  
🧠 Intelligence Engine  
🗄 SQLite Scan Database  
⏱ Scan Scheduler  
🌍 Distributed scanning support  

---

# 🏗 Architecture

Cyber Framework follows a **modular architecture**.


```
         +-------------------+
         |      main.py      |
         +---------+---------+
                   |
                   v
           +--------------+
           |   Console    |
           +--------------+
                   |
                   v
            +-----------+
            | Command   |
            |  Parser   |
            +-----------+
                   |
      +------------+-------------+
      |                          |
      v                          v


+---------------+          +---------------+
|  Core Engine  |          |    Modules    |
+---------------+          +---------------+
|               |          |               |
| Attack Chain  |          | Recon         |
| Intelligence  |          | Scan          |
| Scheduler     |          | Web Scan      |
| Database      |          | Exploit       |
| Attack Graph  |          | Discovery     |         
| Intelligence  |          | Enumeration   |
+---------------+          +---------------+ 

```

Detailed architecture available in:

📄 `docs/architecture.md`

---

# 📁 Project Structure

```

cyber-framework/
│
|── README.md
├── main.py
├── requirements.txt
├── config.json
│
├── core/
│   ├── console.py
│   ├── command_parser.py
│   ├── module_loader.py
│   ├── attack_chain.py
│   ├── progress_engine.py
│   ├── session_manager.py
│   ├── intelligence_engine.py
│   ├── attack_graph.py
│   ├── database.py
│   ├── scheduler.py
|   |── advanced_console.py
|   |── console_style.py
|   |── logger.py
|   |── man_viewer.py
|   |── module_info.py
|   |── os_detection.py
|   |── output.py
|   |── pipeline.py
|   |── report.py
|   |── syntax_highligher.py
|   |── tool_detection.py
|   |── utils.py
│   └── distributed_controller.py
│
├── modules/
│   ├── recon.py
│   ├── scan.py
│   ├── web_scan.py
│   ├── exploit.py
│   └── intelligence.py
│
|──man/
|   |── recon.man
|   |── scan.man
|   |── web_scan.man
|   └── exploit.man
├── ui/
│   └── banner.py
│
├── data/
│   ├── scan.db
│   └── command_history.txt
│
└── docs/
├── architecture.md
└── usage.md

```

---

# ⚙️ Installation

Clone repository:

```

git clone https://github.com/Bhuvaneshkumar1/cyber-framework.git
cd cyber-framework

```

create virtual environment

```
python -m venv venv

```

Install dependencies:

```

pip install -r requirements.txt

```

---

# 📦 Dependencies

Major dependencies used in this project:

+ Python 3.10+
+ requests
+ rich
+ prompt_toolkit
+ sqlite3

# ▶️ Running the Framework

```

python main.py

```

Select mode:

```

Beginner Mode
Advanced Console

```

---

# 🟢 Beginner Mode

Menu-driven operation.

Example:

```

Select Mode → Beginner Mode
Target → example.com
Select Operation → Recon / Scan / Web Scan / Exploit / Attack Chain

```

---

# 🎯 Use Cases

Cyber Framework can be used for:

 1. Learning penetration testing workflows  
 2. Practicing reconnaissance and scanning techniques  
 3. Building custom cybersecurity modules  
 4. Demonstrating attack chain automation  
 5. Security research and experimentation
--- 

# 💻 Advanced Console Mode

Professional CLI console.

Example:

```

cyber> show modules

```
```

Available Modules
recon
scan
web_scan
exploit
discovery
enumeration
intelligence

```

Select module:

```

cyber> use recon

```

Set target:

```

cyber(recon)> set target example.com

```

Run module:

```

cyber(recon)> run

```

---
# 🔐 Security Philosophy

Cyber Framework follows a modular offensive security philosophy:

1. Discover the target surface
2. Enumerate services
3. Analyze vulnerabilities
4. Build an attack path
5. Execute exploitation chain

+ This approach mirrors real-world penetration testing methodologies.
---

# ⚔️ Automatic Attack Chain

Runs a full automated pipeline:

```

Recon
↓
Scan
↓
Web Scan
↓
Exploit

```

Command:

```

cyber> set target example.com
cyber> run attack_chain

```

---
---

# 📊 Attack Graph Visualization

Cyber Framework generates a logical **attack graph** representing relationships between discovered assets and vulnerabilities.

Example flow:

Target Domain
↓
Resolved IP
↓
Open Ports
↓
Detected Services
↓
Potential Exploits

This allows researchers to understand:

+ Attack paths
+ Service exposure
+ Exploitation opportunities  
---

# ⌨️ Console Features

| Feature | Description |
|------|-------------|
| TAB completion | Auto-complete commands |
| Syntax highlighting | Colored commands |
| History persistence | Arrow key navigation |
| Dynamic prompts | `cyber(recon)>` style |

Example:

```

cyber(recon)> set target google.com
cyber(recon)> run

```

---
---

# 🧪 Example Workflow

Example penetration testing workflow using Cyber Framework.

Step 1 — Start the framework

cyber> show modules

Step 2 — Select reconnaissance module

cyber> use recon

Step 3 — Set target

cyber(recon)> set target example.com

Step 4 — Execute module

cyber(recon)> run

Step 5 — Run full attack chain
```
cyber> set target example.com
cyber> run attack_chain
```
---

# 🧩 Available Modules

| Module | Purpose |
|------|---------|
| recon | DNS & domain reconnaissance |
| scan | Network port scanning |
| web_scan | Web vulnerability scanning |
| exploit | Exploitation phase |
| intelligence | Target intelligence gathering |

---

# 💾 Data Storage

Framework stores persistent data:

```

data/scan.db
data/command_history.txt

```

---

# 📚 Documentation

Additional documentation:

📄 `docs/architecture.md`  
📄 `docs/usage.md`

---

# 🛠 Troubleshooting

Common issues and solutions.

**Issue:** Modules not loading

**Solution:** Check the modules directory and ensure Python files follow the module structure.

Issue: Command history not saved

**Solution:** Ensure the `data/command_history.txt` file exist
---

# 🧑‍💻 Author

Developed as a **modular cybersecurity framework for learning and research purposes.**

---

# 📊 Project Statistics

Project metrics:

+ Language: Python
+ Architecture: Modular CLI Framework
+ Database: SQLite
+ Interface: Interactive Console
+ Modules: Recon, Scan, Web Scan, Exploit, Intelligence
---
# ⚠️ Disclaimer

This tool is intended **for educational and authorized security testing only**.

Do **NOT** use this tool against systems without permission.

---

# ⭐ Support the Project

If you find this project useful:

+ ⭐ Star the repository  
+ 🍴 Fork the project  
+ 🛠 Contribute modules  
+ 🐞 Report issues
---
# 🔧 Planned Features

Future improvements planned for Cyber Framework:

+ Machine learning assisted vulnerability detection
+ AI-assisted attack chain planning
+ Web dashboard interface
+ API based distributed scanning nodes
+ Integration with vulnerability scanners
+ Automated report generation
---
# 📜 License

MIT License

---

# 🏆 Project Highlights

Cyber Framework demonstrates several advanced engineering concepts:

• Modular cybersecurity architecture  
• Interactive CLI framework design  
• Automated attack chain orchestration  
• Distributed scanning capability  
• Intelligence driven reconnaissance  

The project is designed as a **research oriented penetration testing framework** and learning platform for cybersecurity practitioners.
---

# 👨‍💻 Contributors

- Bhuvaneshkumar
