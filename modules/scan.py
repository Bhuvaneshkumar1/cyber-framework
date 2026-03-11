import subprocess
from core.os_detection import get_os
from core.tool_detection import tool_exists
from core.intelligence_engine import analyze
from core.attack_graph import add_port

def run(target):
    system = get_os()
    if system == "linux" and tool_exists("nmap"):
        result = subprocess.run(
            [
                "sudo",
                "nmap",
                "-sS",
                "-p-",
                "-T4",
                "-A",
                "-Pn",
                target
            ],
            capture_output=True,
            text=True
        )
        print(result.stdout)
        # Analyze Nmap output
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                port = int(line.split("/")[0])
                # Intelligence engine
                finding = analyze(port)
                print(f"[INTELLIGENCE] {finding}")
                # Attack graph
                add_port(port)
    else:
        print("Basic scan unavailable")