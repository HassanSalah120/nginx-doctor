"""SQLite database connection and initialization.

Thread safety: Uses threading.local for per-thread connections.
No check_same_thread=False — each thread gets its own connection.
All writes use explicit transactions.

DB location: ./data/nginx_doctor.db (created automatically).
"""

import sqlite3
import threading
from pathlib import Path

from nginx_doctor.storage.models import ALL_SCHEMAS

# Default database path (relative to CWD)
_DEFAULT_DB_DIR = Path("./data")
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "nginx_doctor.db"

# Thread-local storage for connections
_local = threading.local()

# Module-level DB path (can be overridden for testing)
_db_path: Path = _DEFAULT_DB_PATH


def set_db_path(path: Path | str) -> None:
    """Override the database path (useful for testing).

    Must be called before init_db() or get_db().
    """
    global _db_path
    _db_path = Path(path)


def get_db_path() -> Path:
    """Return the current database file path."""
    return _db_path


def init_db() -> None:
    """Initialize the database: create directory, file, and all tables.

    Safe to call multiple times (uses CREATE TABLE IF NOT EXISTS).
    """
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(_db_path)
    try:
        for ddl in ALL_SCHEMAS:
            conn.execute(ddl)
        conn.commit()
    finally:
        conn.close()


def get_db() -> sqlite3.Connection:
    """Get a thread-local database connection.

    Each thread gets its own connection via threading.local.
    Connections are reused within the same thread.
    Row factory is set to sqlite3.Row for dict-like access.
    """
    conn = getattr(_local, "connection", None)
    if conn is None:
        conn = _connect(_db_path)
        _local.connection = conn
    return conn


def close_db() -> None:
    """Close the thread-local connection (if any)."""
    conn = getattr(_local, "connection", None)
    if conn is not None:
        conn.close()
        _local.connection = None


def _connect(path: Path) -> sqlite3.Connection:
    """Create a new SQLite connection with preferred settings."""
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn
