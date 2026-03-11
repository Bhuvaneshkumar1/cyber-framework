import datetime

def log(msg):
    with open("scan.log","a") as f:
        f.write(f"{datetime.datetime.now()} : {msg}\n")