
# 📖 Cyber Framework Usage Guide

This guide explains how to use **Cyber Framework** in both Beginner Mode and Advanced Console Mode.

---

# ▶️ Starting the Framework

Run the framework:

```

python main.py

```

You will be prompted to select a mode:

```

Select Mode

1. Beginner Mode
2. Advanced Console

```

---

# 🟢 Beginner Mode

Beginner mode provides a **menu-driven interface** for easy navigation.

Workflow:

```

Select Mode → Beginner Mode
Enter Target → example.com
Select Operation

```

Available operations:

- Recon
- Scan
- Web Scan
- Exploit
- Full Pipeline
- Automatic Attack Chain

Example:

```

Target: example.com
Operation: Recon

```

The framework will execute the selected module automatically.

---

# 💻 Advanced Console Mode

Advanced Console Mode provides a **professional interactive CLI**.

Example prompt:

```

cyber>

```

---

# 📋 View Available Modules

```

cyber> show modules

```

Example output:

```

Available Modules

recon
scan
web_scan
exploit
discovery
enumeration
intelligence
attack_chain

```

---

# 🧩 Select a Module

Use the `use` command.

```

cyber> use recon

```

Prompt changes:

```

cyber(recon)>

```

---

# 🎯 Set Target

Set the target domain or IP.

```

cyber(recon)> set target example.com

```

---

# ▶️ Run the Module

```

cyber(recon)> run

```

The selected module will execute against the target.

---

# ⚔️ Running the Automatic Attack Chain

The attack chain executes multiple phases automatically.

Pipeline:

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

# ⌨️ Console Features

Cyber Framework includes several advanced console features.

---

## TAB Auto-completion

Press **TAB** to auto-complete commands.

Example:

```

cyber> sh[TAB]

```

Result:

```

show modules

```

---

## Command History

Use arrow keys to navigate previous commands.

```

↑  previous command
↓  next command

```

Command history is stored in:

```

data/command_history.txt

```

---

## Syntax Highlighting

Commands are colorized while typing.

Example:

```

cyber> set target google.com

```

Colors:

- commands → highlighted
- keywords → highlighted
- arguments → normal text

---

# 🔍 Example Workflow

Typical penetration testing workflow:

```

cyber> show modules
cyber> use recon
cyber(recon)> set target example.com
cyber(recon)> run

cyber> use scan
cyber(scan)> run

```

Or run automated attack chain:

```

cyber> set target example.com
cyber> run attack_chain

```

---

# 📊 Scan Results

Scan data and results are stored in:

```

data/scan.db

```

Command history:

```

data/command_history.txt

```

---

# 🧩 Adding New Modules

To add a new module:

1. Create a file inside:

```

modules/

```

Example:

```

modules/my_module.py

```

2. Implement the required function:

```

def run(target):
print("Running module on", target)

```

3. Restart the framework.

The module will appear automatically:

```

cyber> show modules

```

---

# ❌ Exiting the Framework

Exit the console with:

```

cyber> exit

```

---

# ⚠️ Important Notes

- Always set a target before running modules.
- Some modules require external tools installed.
- Ensure you have permission before scanning systems.

---

# 📚 Additional Documentation

For more details:

- `docs/architecture.md`
- `README.md`
