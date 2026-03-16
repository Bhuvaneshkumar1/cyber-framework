import subprocess
import platform
import os


def show_man(module):

    script = os.path.join("core", "man_viewer.py")
    system = platform.system()

    if system == "Windows":

        subprocess.Popen(
            ["cmd", "/c", "start", "python", script, module]
        )

    elif system == "Linux":

        subprocess.Popen(
            ["x-terminal-emulator", "-e", f"python3 {script} {module}"],
            shell=True
        )