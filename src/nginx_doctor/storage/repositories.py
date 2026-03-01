"""Repository classes for CRUD operations on the storage layer.

All writes use explicit transactions. Read operations return
typed dataclass records.
"""

import json
from datetime import datetime
from typing import Any

from nginx_doctor.storage.db import get_db
from nginx_doctor.storage.models import (
    CorrelationRecord,
    FindingRecord,
    JobLogRecord,
    ScanJobRecord,
    ServerRecord,
)


_UNSET = object()


class ServerRepository:
    """CRUD operations for the servers table."""

    def create(
        self,
        name: str,
        host: str,
        port: int = 22,
        username: str = "root",
        password: str | None = None,
        key_path: str | None = None,
        tags: str = "",
    ) -> int:
        """Insert a new server record. Returns the new server ID."""
        db = get_db()
        cursor = db.execute(
            """INSERT INTO servers (name, host, port, username, password, key_path, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, host, port, username, password, key_path, tags),
        )
        db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def get_all(self) -> list[ServerRecord]:
        """Return all servers ordered by creation date descending."""
        db = get_db()
        rows = db.execute(
            "SELECT * FROM servers ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_by_id(self, server_id: int) -> ServerRecord | None:
        """Return a server by ID, or None if not found."""
        db = get_db()
        row = db.execute(
            "SELECT * FROM servers WHERE id = ?", (server_id,)
        ).fetchone()
        return self._row_to_record(row) if row else None

    def delete(self, server_id: int) -> bool:
        """Delete a server by ID. Returns True if a row was deleted."""
        db = get_db()
        cursor = db.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        db.commit()
        return cursor.rowcount > 0

    def update(
        self,
        server_id: int,
        *,
        name: str | None = None,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: Any = _UNSET,
        key_path: Any = _UNSET,
        tags: str | None = None,
    ) -> bool:
        """Update a server record. Returns True if a row was updated.

        Notes:
            - Passing password=None will clear the stored password.
            - Passing key_path=None will clear the stored key path.
        """
        db = get_db()
        updates: list[str] = []
        params: list[Any] = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if host is not None:
            updates.append("host = ?")
            params.append(host)
        if port is not None:
            updates.append("port = ?")
            params.append(port)
        if username is not None:
            updates.append("username = ?")
            params.append(username)
        if password is not _UNSET:
            updates.append("password = ?")
            params.append(password)
        if key_path is not _UNSET:
            updates.append("key_path = ?")
            params.append(key_path)
        if tags is not None:
            updates.append("tags = ?")
            params.append(tags)

        if not updates:
            return False

        params.append(server_id)
        cursor = db.execute(
            f"UPDATE servers SET {', '.join(updates)} WHERE id = ?",
            params,
        )
        db.commit()
        return cursor.rowcount > 0

    @staticmethod
    def _row_to_record(row: Any) -> ServerRecord:
        return ServerRecord(
            id=row["id"],
            name=row["name"],
            host=row["host"],
            port=row["port"],
            username=row["username"],
            password=row["password"] if "password" in row.keys() else None,
            key_path=row["key_path"],
            tags=row["tags"] or "",
            created_at=row["created_at"] or "",
        )


class ScanJobRepository:
    """CRUD operations for the scan_jobs table."""

    def create(self, server_id: int) -> int:
        """Create a new scan job with status=queued. Returns job ID."""
        db = get_db()
        cursor = db.execute(
            "INSERT INTO scan_jobs (server_id, status) VALUES (?, 'queued')",
            (server_id,),
        )
        db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def update_status(
        self,
        job_id: int,
        status: str | None = None,
        *,
        score: int | None = None,
        summary: str | None = None,
        diagnosis_json: str | None = None,
        raw_report_path: str | None = None,
        error_message: str | None = None,
        progress: int | None = None,
    ) -> None:
        """Update job status and optional result fields."""
        db = get_db()
        now = datetime.now().isoformat()

        updates = []
        params: list[Any] = []

        if status is not None:
            updates.append("status = ?")
            params.append(status)
            if status == "running":
                updates.append("started_at = ?")
                params.append(now)
            if status in ("success", "failed", "cancelled"):
                updates.append("finished_at = ?")
                params.append(now)

        if score is not None:
            updates.append("score = ?")
            params.append(score)
        if summary is not None:
            updates.append("summary = ?")
            params.append(summary)
        if diagnosis_json is not None:
            updates.append("diagnosis_json = ?")
            params.append(diagnosis_json)
        if raw_report_path is not None:
            updates.append("raw_report_path = ?")
            params.append(raw_report_path)
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if progress is not None:
            updates.append("progress = ?")
            params.append(progress)

        if not updates:
            return

        params.append(job_id)
        db.execute(
            f"UPDATE scan_jobs SET {', '.join(updates)} WHERE id = ?",
            params,
        )
        db.commit()

    def get_all(self, limit: int = 50) -> list[ScanJobRecord]:
        """Return all jobs with server info, most recent first."""
        db = get_db()
        rows = db.execute(
            """SELECT j.*, s.name as server_name, s.host as server_host
               FROM scan_jobs j
               LEFT JOIN servers s ON j.server_id = s.id
               ORDER BY j.created_at DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_by_id(self, job_id: int) -> ScanJobRecord | None:
        """Return a job by ID with server info, or None."""
        db = get_db()
        row = db.execute(
            """SELECT j.*, s.name as server_name, s.host as server_host
               FROM scan_jobs j
               LEFT JOIN servers s ON j.server_id = s.id
               WHERE j.id = ?""",
            (job_id,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def get_by_server_id(self, server_id: int, limit: int = 10) -> list[ScanJobRecord]:
        """Return jobs for a specific server."""
        db = get_db()
        rows = db.execute(
            """SELECT j.*, s.name as server_name, s.host as server_host
               FROM scan_jobs j
               LEFT JOIN servers s ON j.server_id = s.id
               WHERE j.server_id = ?
               ORDER BY j.created_at DESC
               LIMIT ?""",
            (server_id, limit),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_latest_job(self) -> ScanJobRecord | None:
        """Return the most recent scan job."""
        db = get_db()
        row = db.execute(
            """SELECT j.*, s.name as server_name, s.host as server_host
               FROM scan_jobs j
               LEFT JOIN servers s ON j.server_id = s.id
               ORDER BY j.created_at DESC
               LIMIT 1""",
        ).fetchone()
        return self._row_to_record(row) if row else None

    @staticmethod
    def _row_to_record(row: Any) -> ScanJobRecord:
        return ScanJobRecord(
            id=row["id"],
            server_id=row["server_id"],
            status=row["status"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            score=row["score"],
            summary=row["summary"],
            diagnosis_json=row["diagnosis_json"],
            raw_report_path=row["raw_report_path"],
            error_message=row["error_message"],
            progress=row["progress"],
            created_at=row["created_at"] or "",
            server_name=row["server_name"] if "server_name" in row.keys() else None,
            server_host=row["server_host"] if "server_host" in row.keys() else None,
        )


class FindingRepository:
    """CRUD operations for the findings table."""

    def bulk_insert(self, job_id: int, findings: list[dict[str, Any]]) -> None:
        """Insert multiple finding records in a single transaction.

        Each dict should have: rule_id, severity, title, category,
        component, description, evidence_ref, evidence_json, recommendation.
        """
        db = get_db()
        db.executemany(
            """INSERT INTO findings (job_id, rule_id, category, component, severity, title,
                                     description, evidence_ref, evidence_json, recommendation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    job_id,
                    f.get("rule_id", "unknown"),
                    f.get("category"),
                    f.get("component"),
                    f.get("severity", "info"),
                    f.get("title", ""),
                    f.get("description"),
                    f.get("evidence_ref"),
                    f.get("evidence_json"),
                    f.get("recommendation"),
                )
                for f in findings
            ],
        )
        db.commit()

    def get_by_job_id(self, job_id: int) -> list[FindingRecord]:
        """Return all findings for a job."""
        db = get_db()
        rows = db.execute(
            "SELECT * FROM findings WHERE job_id = ? ORDER BY id",
            (job_id,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_by_severity(
        self, severity: str, job_id: int | None = None
    ) -> list[FindingRecord]:
        """Return findings filtered by severity, optionally by job."""
        db = get_db()
        if job_id is not None:
            rows = db.execute(
                "SELECT * FROM findings WHERE severity = ? AND job_id = ? ORDER BY id",
                (severity, job_id),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM findings WHERE severity = ? ORDER BY id",
                (severity,),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: Any) -> FindingRecord:
        return FindingRecord(
            id=row["id"],
            job_id=row["job_id"],
            rule_id=row["rule_id"],
            category=row["category"],
            component=row["component"],
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            evidence_ref=row["evidence_ref"],
            evidence_json=row["evidence_json"],
            recommendation=row["recommendation"],
            created_at=row["created_at"] or "",
        )


class JobLogRepository:
    """Append-only log storage for job progress."""

    def append(self, job_id: int, message: str) -> None:
        """Append a log message for a job."""
        db = get_db()
        db.execute(
            "INSERT INTO job_logs (job_id, message) VALUES (?, ?)",
            (job_id, message),
        )
        db.commit()

    def get_by_job_id(self, job_id: int, after_id: int = 0) -> list[JobLogRecord]:
        """Return logs for a job, optionally only those after a given ID.

        The after_id parameter supports efficient polling — clients can
        pass the last seen log ID to only get new entries.
        """
        db = get_db()
        rows = db.execute(
            "SELECT * FROM job_logs WHERE job_id = ? AND id > ? ORDER BY id",
            (job_id, after_id),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: Any) -> JobLogRecord:
        return JobLogRecord(
            id=row["id"],
            job_id=row["job_id"],
            timestamp=row["timestamp"] or "",
            message=row["message"],
        )


class CorrelationRepository:
    """CRUD operations for the correlations table."""

    def bulk_insert(self, job_id: int, correlations: list[dict[str, Any]]) -> None:
        """Insert multiple correlation records.

        Each dict should have: correlation_id, root_cause_hypothesis,
        blast_radius, confidence, supporting_rule_ids (list), fix_bundle (list).
        """
        db = get_db()
        db.executemany(
            """INSERT INTO correlations (job_id, correlation_id, root_cause_hypothesis,
                                         blast_radius, confidence, supporting_rule_ids,
                                         fix_bundle_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    job_id,
                    c.get("correlation_id", "unknown"),
                    c.get("root_cause_hypothesis"),
                    c.get("blast_radius"),
                    c.get("confidence", 0.0),
                    json.dumps(c.get("supporting_rule_ids", [])),
                    json.dumps(c.get("fix_bundle", [])),
                )
                for c in correlations
            ],
        )
        db.commit()

    def get_by_job_id(self, job_id: int) -> list[CorrelationRecord]:
        """Return all correlations for a job."""
        db = get_db()
        rows = db.execute(
            "SELECT * FROM correlations WHERE job_id = ? ORDER BY id",
            (job_id,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: Any) -> CorrelationRecord:
        return CorrelationRecord(
            id=row["id"],
            job_id=row["job_id"],
            correlation_id=row["correlation_id"],
            root_cause_hypothesis=row["root_cause_hypothesis"],
            blast_radius=row["blast_radius"],
            confidence=row["confidence"],
            supporting_rule_ids=row["supporting_rule_ids"],
            fix_bundle_json=row["fix_bundle_json"],
            created_at=row["created_at"] or "",
        )
