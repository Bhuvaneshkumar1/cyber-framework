module_info = {
    "recon": {
        "tool": "theHarvester / nslookup / socket_dns",
        "command": "theHarvester -d <target> -b google",
        "description": "Passive DNS resolution and open-source infrastructure intelligence gathering."
    },
    "intelligence": {
        "tool": "whois / nslookup / ping",
        "command": "whois <target>, nslookup <target>",
        "description": "Evidence-based target intelligence gathering (factual DNS, whois, and reachability)."
    },
    "scan": {
        "tool": "nmap / socket_scanner",
        "command": "nmap -sT -T3 -Pn --top-ports 100 <target>",
        "description": "Network port and service scanning with safe unprivileged defaults."
    },
    "web_scan": {
        "tool": "nikto / builtin_http_inspector",
        "command": "nikto -h <target> -Tuning 123b",
        "description": "Web server vulnerability scanning and defensive header configuration inspection."
    },
    "exploit": {
        "tool": "sqlmap",
        "command": "sqlmap -u <target> --batch --banner --threads=1",
        "description": "SQL injection testing (explicit intrusive opt-in required)."
    },
    "attack_chain": {
        "tool": "multi_module_orchestrator",
        "command": "run attack_chain [--exploit]",
        "description": "Automated sequential execution: Recon -> Scan -> Web Scan -> (Optional) Exploit."
    },
    "pipeline": {
        "tool": "multi_stage_pipeline",
        "command": "run pipeline [--exploit]",
        "description": "Full end-to-end security pipeline with stage result recording and database storage."
    }
}