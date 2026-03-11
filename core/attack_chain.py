from core.progress_engine import run_with_progress
from modules import recon, scan, web_scan, exploit
from core.logger import log


def run_attack_chain(target):
    print("Starting Automatic Attack Chain")
    log("Attack chain started")
    print("\n===== Recon Phase =====\n")
    run_with_progress("Recon Phase", lambda: recon.run(target+"\n"))
    print("\n===== Scan Phase =====\n")
    run_with_progress("Scan Phase", lambda: scan.run(target))
    print("\n===== Web Scan Phase =====\n")
    run_with_progress("Web Scan Phase", lambda: web_scan.run(target))
    print("\n===== Exploit Phase =====\n")
    run_with_progress("Exploit Phase", lambda: exploit.run(target))
    log("Attack chain completed")
    print("Attack Chain Finished")