from modules import recon, scan, web_scan, exploit

def run_pipeline(target):

    recon.run(target)
    scan.run(target)
    web_scan.run(target)
    exploit.run(target)