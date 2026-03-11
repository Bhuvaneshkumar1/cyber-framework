import subprocess
from core.os_detection import get_os
from core.logger import log


def run(target):

    log(f"Intelligence gathering started for {target}")

    system = get_os()

    print("Gathering target intelligence")

    if system == "linux":

        subprocess.run(["whois", target])

        subprocess.run(["nslookup", target])

    elif system == "windows":

        subprocess.run(["nslookup", target])

        subprocess.run(["ping", target])

    else:

        print("Intelligence module unsupported")