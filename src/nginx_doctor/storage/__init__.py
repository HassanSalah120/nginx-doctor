"""SQLite storage layer for NginxDoctor.

Provides persistent storage for servers, scan jobs, findings, and job logs.
DB file: ./data/nginx_doctor.db (auto-created on startup).
"""

from nginx_doctor.storage.db import get_db, init_db

__all__ = ["get_db", "init_db"]
