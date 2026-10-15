class IntelligenceFinding(dict):
    """
    Structured intelligence observation.
    Maintains rigorous distinction between:
    - observed: Direct empirical measurements (e.g. open port).
    - inferred: Logical deduction based on standard protocol specifications.
    - possibilities: Areas for security verification (NEVER claimed as confirmed vulnerabilities).
    """
    def __init__(self, port: int, service: str, observed: str, inferred: str, possibilities: list[str]):
        super().__init__(
            port=port,
            service=service,
            observed=observed,
            inferred=inferred,
            possibilities=possibilities
        )

    def __str__(self):
        poss_text = "; ".join(self["possibilities"])
        return f"[Observed: {self['observed']}] [Inferred: {self['inferred']}] [Verification Target: {poss_text}]"


PORT_KNOWLEDGE = {
    21: {
        "service": "FTP",
        "observed": "Port 21 listening (File Transfer Protocol)",
        "inferred": "File transfer service active",
        "possibilities": ["Check whether anonymous authentication is permitted by server policy"]
    },
    22: {
        "service": "SSH",
        "observed": "Port 22 listening (Secure Shell)",
        "inferred": "Encrypted remote terminal / administration service active",
        "possibilities": ["Verify SSH protocol version (SSH-2) and authentication policy (key vs password)"]
    },
    80: {
        "service": "HTTP",
        "observed": "Port 80 listening (Hypertext Transfer Protocol)",
        "inferred": "Unencrypted web application server active",
        "possibilities": ["Inspect web server banner, security response headers, and HTTPS redirect enforcement"]
    },
    443: {
        "service": "HTTPS",
        "observed": "Port 443 listening (HTTP over TLS)",
        "inferred": "TLS-encrypted web application server active",
        "possibilities": ["Inspect TLS certificate validity, expiration, and supported cryptographic ciphers"]
    },
    445: {
        "service": "SMB",
        "observed": "Port 445 listening (Server Message Block)",
        "inferred": "Network file sharing and RPC transport endpoint active",
        "possibilities": ["Inspect SMB signing enforcement and guest/anonymous share restrictions"]
    },
    3306: {
        "service": "MySQL",
        "observed": "Port 3306 listening (MySQL Database Server)",
        "inferred": "Relational database service listening on network interface",
        "possibilities": ["Verify network binding restrictions and remote root login policies"]
    },
    3389: {
        "service": "RDP",
        "observed": "Port 3389 listening (Remote Desktop Protocol)",
        "inferred": "Remote desktop management interface active",
        "possibilities": ["Verify Network Level Authentication (NLA) enforcement"]
    },
    8080: {
        "service": "HTTP-Alt",
        "observed": "Port 8080 listening (Alternative HTTP/Proxy)",
        "inferred": "Secondary web service, development server, or application proxy active",
        "possibilities": ["Check for administrative portals, test consoles, or exposed management APIs"]
    }
}


def analyze(port: int) -> IntelligenceFinding:
    """
    Correlate open port with empirical facts, protocol inferences, and verification targets.
    Does NOT assert vulnerability without direct proof.
    """
    if not isinstance(port, int):
        try:
            port = int(port)
        except (ValueError, TypeError):
            return IntelligenceFinding(
                port=0,
                service="Unknown",
                observed="Invalid port format",
                inferred="Unparseable port number",
                possibilities=[]
            )

    info = PORT_KNOWLEDGE.get(port)
    if info:
        return IntelligenceFinding(
            port=port,
            service=info["service"],
            observed=info["observed"],
            inferred=info["inferred"],
            possibilities=info["possibilities"]
        )

    return IntelligenceFinding(
        port=port,
        service=f"Port-{port}",
        observed=f"Port {port} listening",
        inferred="Unknown network protocol or custom application service",
        possibilities=["Perform protocol identification and banner grabbing to identify application"]
    )