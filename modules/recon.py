import subprocess
from core.os_detection import get_os
from core.output import show_output
from core.tool_detection import tool_exists

def run(target):
    system = get_os()
    if system == "linux" and tool_exists("theHarvester"):

        result = subprocess.run(
            ["theHarvester", "-d", target, "-b", "google"],
            capture_output=True,
            text=True
        )
        show_output("Recon Results", result.stdout)
    elif system == "windows":
        result = subprocess.run(
            ["nslookup", target],
            capture_output=True,
            text=True
        )
        show_output("DNS Lookup", result.stdout)