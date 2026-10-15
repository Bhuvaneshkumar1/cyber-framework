import pytest
import socket
import threading
import time
from core.distributed_controller import start_worker, stop_worker


def test_distributed_controller_disabled_by_default():
    # Calling start_worker without explicit enabling in config or params should refuse
    result = start_worker(host=None, port=None, auth_token=None)
    assert result is False


def test_distributed_controller_rejects_bind_all_interfaces():
    # Binding to 0.0.0.0 must be rejected as an insecure exposure
    result = start_worker(host="0.0.0.0", port=9999, auth_token="valid_secret_token_1234")
    assert result is False


def test_distributed_controller_requires_strong_token():
    # Token shorter than 16 characters must be rejected
    result = start_worker(host="127.0.0.1", port=9999, auth_token="short")
    assert result is False


def test_distributed_controller_auth_and_task_execution():
    port = 19090
    token = "secure_test_auth_token_999"

    # Start worker in background thread with single_task=True
    worker_thread = threading.Thread(
        target=start_worker,
        kwargs={"host": "127.0.0.1", "port": port, "auth_token": token, "single_task": True},
        daemon=True
    )
    worker_thread.start()
    time.sleep(0.3)

    try:
        # Test 1: Unauthenticated connection
        s1 = socket.socket()
        s1.connect(("127.0.0.1", port))
        s1.sendall(b"TASK 127.0.0.1\n")
        response1 = s1.recv(1024).decode()
        s1.close()
        assert "Authentication required" in response1

        # Test 2: Invalid token
        s2 = socket.socket()
        s2.connect(("127.0.0.1", port))
        s2.sendall(b"AUTH wrong_token_123\n")
        response2 = s2.recv(1024).decode()
        s2.close()
        assert "Invalid authentication token" in response2

        # Test 3: Valid authentication and valid task
        s3 = socket.socket()
        s3.connect(("127.0.0.1", port))
        s3.sendall(f"AUTH {token}\n".encode())
        auth_ack = s3.recv(1024).decode()
        assert "Authenticated" in auth_ack

        s3.sendall(b"TASK 127.0.0.1\n")
        task_ack = s3.recv(1024).decode()
        s3.close()
        assert "ACCEPTED" in task_ack

    finally:
        stop_worker()
