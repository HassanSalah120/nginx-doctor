"""Data models and schema DDL for the storage layer.

Provides dataclass records for each table and the DDL constants
used by db.py to initialize the database.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# ─── Schema DDL ────────────────────────────────────────────────────────────────

SCHEMA_SERVERS = """
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL DEFAULT 'root',
    password TEXT,
    key_path TEXT,
    tags TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

SCHEMA_SCAN_JOBS = """
CREATE TABLE IF NOT EXISTS scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    started_at TEXT,
    finished_at TEXT,
    score INTEGER,
    summary TEXT,
    diagnosis_json TEXT,
    raw_report_path TEXT,
    error_message TEXT,
    progress INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (server_id) REFERENCES servers(id)
);
"""

SCHEMA_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    category TEXT,
    component TEXT,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence_ref TEXT,
    evidence_json TEXT,
    recommendation TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
);
"""

SCHEMA_JOB_LOGS = """
CREATE TABLE IF NOT EXISTS job_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    message TEXT NOT NULL,
    FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
);
"""

SCHEMA_CORRELATIONS = """
CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    correlation_id TEXT NOT NULL,
    root_cause_hypothesis TEXT,
    blast_radius TEXT,
    confidence REAL,
    supporting_rule_ids TEXT,
    fix_bundle_json TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
);
"""

ALL_SCHEMAS = [SCHEMA_SERVERS, SCHEMA_SCAN_JOBS, SCHEMA_FINDINGS, SCHEMA_JOB_LOGS, SCHEMA_CORRELATIONS]


# ─── Record Dataclasses ───────────────────────────────────────────────────────


@dataclass
class ServerRecord:
    """A registered server."""

    id: int
    name: str
    host: str
    port: int = 22
    username: str = "root"
    password: str | None = None
    key_path: str | None = None
    tags: str = ""
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "key_path": self.key_path,
            "tags": self.tags,
            "created_at": self.created_at,
        }


@dataclass
class ScanJobRecord:
    """A scan job entry."""

    id: int
    server_id: int
    status: str = "queued"
    started_at: str | None = None
    finished_at: str | None = None
    score: int | None = None
    summary: str | None = None
    diagnosis_json: str | None = None
    raw_report_path: str | None = None
    error_message: str | None = None
    progress: int = 0
    created_at: str = ""
    # Joined fields (optional, populated by repository)
    server_name: str | None = None
    server_host: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "server_id": self.server_id,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "score": self.score,
            "summary": self.summary,
            "diagnosis_json": self.diagnosis_json,
            "raw_report_path": self.raw_report_path,
            "error_message": self.error_message,
            "progress": self.progress,
            "created_at": self.created_at,
        }
        if self.server_name is not None:
            d["server_name"] = self.server_name
        if self.server_host is not None:
            d["server_host"] = self.server_host
        return d


@dataclass
class FindingRecord:
    """A stored finding from a scan job."""

    id: int
    job_id: int
    rule_id: str
    severity: str
    title: str
    category: str | None = None
    component: str | None = None
    description: str | None = None
    evidence_ref: str | None = None
    evidence_json: str | None = None
    recommendation: str | None = None
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "rule_id": self.rule_id,
            "category": self.category,
            "component": self.component,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence_ref": self.evidence_ref,
            "evidence_json": self.evidence_json,
            "recommendation": self.recommendation,
            "created_at": self.created_at,
        }


@dataclass
class JobLogRecord:
    """A log entry for a job."""

    id: int
    job_id: int
    timestamp: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "timestamp": self.timestamp,
            "message": self.message,
        }


@dataclass
class CorrelationRecord:
    """A synthesized finding / root cause analysis."""

    id: int
    job_id: int
    correlation_id: str
    root_cause_hypothesis: str | None = None
    blast_radius: str | None = None
    confidence: float = 0.0
    supporting_rule_ids: str | None = None  # JSON array
    fix_bundle_json: str | None = None      # JSON array
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "correlation_id": self.correlation_id,
            "root_cause_hypothesis": self.root_cause_hypothesis,
            "blast_radius": self.blast_radius,
            "confidence": self.confidence,
            "supporting_rule_ids": self.supporting_rule_ids,
            "fix_bundle_json": self.fix_bundle_json,
            "created_at": self.created_at,
        }
