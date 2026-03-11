import subprocess
from core.os_detection import get_os

def run(domain):
    targets=[]
    if get_os()=="linux":
        result=subprocess.run(
            ["nslookup",domain],
            capture_output=True,
            text=True
        )
        for line in result.stdout.splitlines():
            if "Address:" in line:
                ip=line.split()[-1]
                targets.append(ip)
    return targets