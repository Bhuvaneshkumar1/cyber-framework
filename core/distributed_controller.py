import socket

PORT=9090

def start_worker():
    s=socket.socket()
    s.bind(("0.0.0.0",PORT))
    s.listen()
    print("Worker listening")
    while True:
        conn,addr=s.accept()
        target=conn.recv(1024).decode()
        print("Received task:",target)
        conn.close()