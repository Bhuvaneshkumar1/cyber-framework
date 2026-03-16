module_info = {
    "recon":{
        "tool":"theHarvester",
        "command": "theHarvester -d <target> -b google"
    },
    "intelligence":{
        "tool":"whois / nslookup",
        "command":"whois <target>, nslookup <target>"
    },
    "scan":{
        "tool":"nmap",
        "command":"sudo nmp -sS -p- -T4 -A -Pn <target>"
    },
    "web_scan":{
        "tool":"nikto",
        "command":"nikto -h <target>"
    },
    "exploit":{
        "tool":"sqlmap",
        "command":"sqlmap -u <target> --batch"
    }
}