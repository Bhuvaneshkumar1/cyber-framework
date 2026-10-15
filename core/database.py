import sqlite3
import datetime
from pathlib import Path
from core.utils import PROJECT_ROOT

DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "scan.db"


def get_db_path() -> Path:
    """Return the absolute path to the SQLite database."""
    DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return DEFAULT_DB_PATH


def init_db(db_path: Path | str | None = None) -> bool:
    """
    Initialize database schema and perform backwards-compatible migrations.
    Preserves existing scans table while ensuring timestamp and ID columns exist.
    """
    path = Path(db_path) if db_path else get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with sqlite3.connect(str(path)) as conn:
            c = conn.cursor()

            # Check if table already exists
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
            table_exists = c.fetchone() is not None

            if not table_exists:
                c.execute("""
                CREATE TABLE scans(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    service TEXT,
                    timestamp TEXT
                )
                """)
            else:
                # Migration: verify existing columns and add missing ones
                c.execute("PRAGMA table_info(scans)")
                existing_cols = [col[1] for col in c.fetchall()]

                if "timestamp" not in existing_cols:
                    c.execute("ALTER TABLE scans ADD COLUMN timestamp TEXT")

            conn.commit()
            return True
    except Exception as e:
        print(f"[!] Database initialization error: {e}")
        return False


def save_port(target: str, port: int, service: str = "unknown", timestamp: str | None = None, db_path: Path | str | None = None) -> bool:
    """
    Save discovered open port and service to database with transaction management and validation.
    """
    if not target or not isinstance(target, str):
        return False

    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            return False
    except (ValueError, TypeError):
        return False

    ts = timestamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    path = Path(db_path) if db_path else get_db_path()

    # Ensure DB is initialized before opening connection
    init_db(path)

    try:
        with sqlite3.connect(str(path)) as conn:
            c = conn.cursor()

            c.execute("PRAGMA table_info(scans)")
            existing_cols = [col[1] for col in c.fetchall()]

            if "timestamp" in existing_cols:
                c.execute(
                    "INSERT INTO scans (target, port, service, timestamp) VALUES (?, ?, ?, ?)",
                    (target.strip(), port_num, str(service).strip(), ts)
                )
            else:
                c.execute(
                    "INSERT INTO scans (target, port, service) VALUES (?, ?, ?)",
                    (target.strip(), port_num, str(service).strip())
                )
            conn.commit()
            return True
    except Exception as e:
        print(f"[!] Database write error: {e}")
        return False


def get_scans_by_target(target: str, db_path: Path | str | None = None) -> list[dict]:
    """Retrieve all recorded scan findings for a specific target."""
    if not target:
        return []

    path = Path(db_path) if db_path else get_db_path()
    if not path.exists():
        return []

    try:
        with sqlite3.connect(str(path)) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM scans WHERE target = ? ORDER BY port ASC", (target.strip(),))
            rows = c.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"[!] Database read error: {e}")
        return []


def get_all_scans(db_path: Path | str | None = None) -> list[dict]:
    """Retrieve all recorded scan records from the database."""
    path = Path(db_path) if db_path else get_db_path()
    if not path.exists():
        return []

    try:
        with sqlite3.connect(str(path)) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM scans ORDER BY target ASC, port ASC")
            rows = c.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"[!] Database read error: {e}")
        return []