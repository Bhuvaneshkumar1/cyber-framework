def analyze(port):

    findings={
        21:"FTP detected → check anonymous login",
        22:"SSH detected → brute force possible",
        80:"HTTP server detected → web attack surface",
        443:"HTTPS service detected",
        445:"SMB detected → possible SMB vulnerabilities"
    }

    return findings.get(port,"Unknown service")