import subprocess
from core.tool_detection import tool_exists
from core.os_detection import get_os
from core.logger import log


def run(network):

    log(f"Discovery started on {network}")

    system = get_os()

    if system == "linux" and tool_exists("nmap"):

        print("Running network discovery")

        subprocess.run([
            "sudo",
            "nmap",
            "-sn",
            network
        ])

    elif system == "windows":

        print("Network discovery limited on Windows")

        subprocess.run([
            "ping",
            network
        ])

    else:

        print("Discovery tool unavailable")