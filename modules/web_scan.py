import subprocess
from core.os_detection import get_os
from core.tool_detection import tool_exists

def run(target):
    if get_os() == "linux" and tool_exists("nikto"):
        subprocess.run(["nikto","-h",target])
    else:
        print("Nikto unavailable")