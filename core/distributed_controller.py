import socket
import hmac
from core.utils import get_config, validate_target, is_target_in_scope
from core.logger import log

_server_socket = None
_running = False


def start_worker(host: str | None = None, port: int | None = None, auth_token: str | None = None, single_task: bool = False) -> bool:
    """
    Start the distributed worker listener.
    Security controls:
    1. Disabled by default in config.json.
    2. Defaults to loopback address (127.0.0.1).
    3. Requires strict token authentication.
    4. Validates all incoming task targets against scope policy.
    """
    global _server_socket, _running
    cfg = get_config()
    dist_cfg = cfg.get("distributed", {})

    # Check if enabled
    if not dist_cfg.get("enabled", False) and not (host and auth_token):
        msg = (
            "[!] Distributed worker is DISABLED by default in config.json. "
            "To enable, configure 'distributed.enabled: true' and set a strong 'auth_token'."
        )
        print(msg)
        log("Distributed worker start rejected: disabled in configuration.")
        return False

    bind_host = host or dist_cfg.get("bind_host", "127.0.0.1")
    bind_port = port or dist_cfg.get("bind_port", 9090)
    token = auth_token or dist_cfg.get("auth_token", "")

    # Forbid public exposure without strong authentication
    if bind_host in ("0.0.0.0", "::"):
        print("[!] Security Violation: Refusing to bind distributed worker to all interfaces (0.0.0.0). Use 127.0.0.1.")
        return False

    if not token or len(token) < 16:
        print("[!] Security Violation: A strong 'auth_token' (minimum 16 characters) is required to start the worker.")
        return False

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(5.0)
        s.bind((bind_host, bind_port))
        s.listen(5)
        _server_socket = s
        _running = True
        print(f"[*] Distributed worker listening on {bind_host}:{bind_port} (Auth Required)")
        log(f"Distributed worker started on {bind_host}:{bind_port}")

        while _running:
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue

            conn.settimeout(5.0)
            try:
                # Expect AUTH <token>\n
                auth_data = conn.recv(1024).decode("utf-8", errors="ignore").strip()
                if not auth_data.startswith("AUTH "):
                    conn.sendall(b"ERROR: Authentication required\n")
                    conn.close()
                    continue

                client_token = auth_data[5:].strip()
                if not hmac.compare_digest(client_token.encode(), token.encode()):
                    conn.sendall(b"ERROR: Invalid authentication token\n")
                    conn.close()
                    log(f"Unauthorized task attempt from {addr}")
                    continue

                conn.sendall(b"OK: Authenticated. Send TASK <target>\n")

                # Receive task
                task_data = conn.recv(1024).decode("utf-8", errors="ignore").strip()
                if not task_data.startswith("TASK "):
                    conn.sendall(b"ERROR: Expected TASK <target>\n")
                    conn.close()
                    continue

                raw_target = task_data[5:].strip()
                valid, clean_target = validate_target(raw_target)
                if not valid:
                    conn.sendall(f"ERROR: Invalid target '{raw_target}': {clean_target}\n".encode())
                    conn.close()
                    continue

                in_scope, scope_msg = is_target_in_scope(clean_target)
                if not in_scope:
                    conn.sendall(f"ERROR: Target out of scope: {scope_msg}\n".encode())
                    conn.close()
                    continue

                print(f"[+] Worker accepted authorized task from {addr}: {clean_target}")
                log(f"Worker accepted task: {clean_target} from {addr}")
                conn.sendall(f"ACCEPTED: Task scheduled for {clean_target}\n".encode())
                conn.close()

                if single_task:
                    break
            except Exception as conn_err:
                log(f"Error handling worker connection from {addr}: {conn_err}")
                try:
                    conn.close()
                except Exception:
                    pass

        return True
    except Exception as e:
        print(f"[!] Worker error: {e}")
        log(f"Distributed worker error: {e}")
        return False
    finally:
        stop_worker()


def stop_worker():
    """Safely terminate the worker socket."""
    global _server_socket, _running
    _running = False
    if _server_socket:
        try:
            _server_socket.close()
        except Exception:
            pass
        _server_socket = None