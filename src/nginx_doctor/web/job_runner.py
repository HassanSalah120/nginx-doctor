"""DB-backed scan job runner with ThreadPoolExecutor.

Executes scan jobs in background threads, logging progress to SQLite.
max_workers=1 by default (SSH scans are heavy). Configurable via
NGINX_DOCTOR_MAX_WORKERS environment variable.
"""

import json
import os
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from nginx_doctor.ai.diagnoser import generate_diagnosis
from nginx_doctor.connector.ssh import SSHConfig, SSHConnector
from nginx_doctor.storage.repositories import (
    CorrelationRepository,
    FindingRepository,
    JobLogRepository,
    ScanJobRepository,
    ServerRepository,
)

class JobCancelledError(Exception):
    """Raised when a job is requested to be cancelled."""
    pass

class JobTimeoutError(Exception):
    """Raised when a job exceeds the maximum execution time."""
    pass



# Report output directory (under ./data/reports/ to avoid mixing with repo root)
_REPORTS_DIR = Path("./data/reports")


def _get_max_workers() -> int:
    """Get max workers from env var, default 1."""
    try:
        return int(os.getenv("NGINX_DOCTOR_MAX_WORKERS", "1"))
    except ValueError:
        return 1


class ScanJobRunner:
    """Background scan job runner backed by SQLite storage.

    Submits scan jobs to a thread pool, tracks status and logs in the DB.
    """

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=_get_max_workers(),
            thread_name_prefix="scan-job",
        )
        self._server_repo = ServerRepository()
        self._job_repo = ScanJobRepository()
        self._finding_repo = FindingRepository()
        self._correlation_repo = CorrelationRepository()
        self._log_repo = JobLogRepository()

    def submit_scan(self, server_id: int) -> int:
        """Submit a scan job for a server. Returns the job ID."""
        # Verify server exists
        server = self._server_repo.get_by_id(server_id)
        if server is None:
            raise ValueError(f"Server with ID {server_id} not found")

        job_id = self._job_repo.create(server_id)
        self._log_repo.append(job_id, "Job queued")
        self._executor.submit(self._run_scan, job_id, server_id)
        return job_id

    def _run_scan(self, job_id: int, server_id: int) -> None:
        """Worker function: execute the full scan pipeline."""
        start_time = time.time()
        job_timeout = int(os.getenv("NGINX_DOCTOR_JOB_TIMEOUT", "600"))

        def check_status() -> None:
            """Check if job was cancelled or timed out."""
            job = self._job_repo.get_by_id(job_id)
            if job and job.status == "cancel_requested":
                raise JobCancelledError("Job was cancelled by user")
            if time.time() - start_time > job_timeout:
                raise JobTimeoutError(f"Job exceeded configured timeout of {job_timeout} seconds")

        try:
            self._job_repo.update_status(job_id, "running", progress=0)
            self._log_repo.append(job_id, "Job started")
            check_status()

            # Load server details
            server = self._server_repo.get_by_id(server_id)
            if server is None:
                raise ValueError(f"Server {server_id} not found")

            self._log_repo.append(
                job_id, f"Connecting to {server.host}:{server.port}..."
            )

            auth_mode = "agent/default keys"
            if server.key_path:
                auth_mode = "key_path"
            elif server.password:
                auth_mode = "password"
            self._log_repo.append(job_id, f"SSH auth mode: {auth_mode}")

            # Build SSH config
            ssh_config = SSHConfig(
                host=server.host,
                user=server.username,
                port=server.port,
                password=server.password,
                key_path=server.key_path,
            )

            # Progress logger
            def log_fn(msg: str) -> None:
                self._log_repo.append(job_id, msg)
                check_status()

            # Execute scan pipeline
            from nginx_doctor.pipeline import run_full_diagnosis, run_full_scan

            with SSHConnector(ssh_config) as ssh:
                log_fn("SSH connection established")
                self._job_repo.update_status(job_id, progress=10)

                # Phase 1: Scan
                log_fn("Starting infrastructure scan...")
                model = run_full_scan(ssh, log_fn=log_fn)
                self._job_repo.update_status(job_id, progress=40)

                # Phase 2: Diagnose
                log_fn("Running analysis and diagnosis...")
                result = run_full_diagnosis(model, ssh, log_fn=log_fn)
                self._job_repo.update_status(job_id, progress=70)

                # Phase 3: Generate HTML report
                log_fn("Generating HTML report...")
                report_path = self._generate_report(
                    job_id, model, result, log_fn
                )
                self._job_repo.update_status(job_id, progress=85)

                # Phase 4: AI diagnosis
                log_fn("Generating AI diagnosis...")
                diagnosis = generate_diagnosis(
                    findings=result.findings,
                    topology=result.topology_snapshot,
                    score=result.score,
                    history=result.trend,
                )
                diagnosis_json = json.dumps(diagnosis.to_dict(), default=str)
                self._job_repo.update_status(job_id, progress=90)

                # Phase 5: Store findings
                log_fn(f"Storing {len(result.findings)} findings...")
                finding_dicts = []
                for f in result.findings:
                    evidence_data = [
                        {
                            "source_file": e.source_file,
                            "line_number": e.line_number,
                            "excerpt": e.excerpt,
                            "command": e.command,
                        }
                        for e in (f.evidence or [])
                    ]
                    finding_dicts.append(
                        {
                            "rule_id": getattr(f, "rule_id", "unknown"),
                            "category": getattr(f, "category", None),
                            "component": getattr(f, "component", None),
                            "severity": f.severity.value
                            if hasattr(f.severity, "value")
                            else str(f.severity),
                            "title": f.condition,
                            "description": f.cause,
                            "evidence_json": json.dumps(evidence_data, default=str),
                            "recommendation": f.treatment,
                            "evidence_ref": evidence_data[0]["source_file"] if evidence_data else None,
                        }
                    )
                self._finding_repo.bulk_insert(job_id, finding_dicts)

                # Phase 5.5: Store correlations (synthesized findings)
                if diagnosis.correlations:
                    log_fn(f"Storing {len(diagnosis.correlations)} synthesized findings...")
                    correlation_records = []
                    for c in diagnosis.correlations:
                        correlation_records.append({
                            "correlation_id": c.correlation_id,
                            "severity": c.severity,
                            "root_cause_hypothesis": c.root_cause_hypothesis,
                            "blast_radius": c.blast_radius,
                            "supporting_rule_ids": ",".join(c.supporting_rule_ids),
                            "fix_bundle_json": json.dumps(c.fix_bundle, default=str),
                            "confidence": c.confidence
                        })
                    self._correlation_repo.bulk_insert(job_id, correlation_records)

                self._job_repo.update_status(job_id, progress=95)

                # Phase 6: Update job as success
                summary = f"{len(result.findings)} findings, score {result.score}/100"
                self._job_repo.update_status(
                    job_id,
                    "success",
                    score=result.score,
                    summary=summary,
                    diagnosis_json=diagnosis_json,
                    raw_report_path=report_path,
                    progress=100,
                )
                self._log_repo.append(job_id, f"Scan complete: {summary}")

        except JobCancelledError as e:
            self._job_repo.update_status(job_id, "cancelled", summary=str(e), error_message=str(e))
            self._log_repo.append(job_id, f"Cancelled: {str(e)}")
        except JobTimeoutError as e:
            self._job_repo.update_status(job_id, "failed", summary="Timed out", error_message=str(e))
            self._log_repo.append(job_id, f"Timeout: {str(e)}")
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            tb = traceback.format_exc()
            self._job_repo.update_status(job_id, "failed", summary=error_msg, error_message=tb)
            self._log_repo.append(job_id, error_msg)
            # Log traceback for debugging (truncated)
            self._log_repo.append(job_id, f"Traceback: {tb[:500]}")

    def _generate_report(
        self,
        job_id: int,
        model: Any,
        result: Any,
        log_fn: Any,
    ) -> str:
        """Generate HTML report and return the file path."""
        from nginx_doctor.actions.html_report import HTMLReportAction

        report_dir = _REPORTS_DIR / str(job_id)
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.html"

        reporter = HTMLReportAction()
        reporter.generate(
            model,
            result.findings,
            output_path=str(report_path),
            ws_inventory=result.ws_inventory,
            trend=result.trend,
            suppressed_findings=result.suppressed_findings,
            waiver_source=result.waiver_source,
        )

        return str(report_path)

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the thread pool."""
        self._executor.shutdown(wait=wait)


# Global singleton (initialized by app.py)
scan_job_runner: ScanJobRunner | None = None


def get_runner() -> ScanJobRunner:
    """Get the global ScanJobRunner instance."""
    global scan_job_runner
    if scan_job_runner is None:
        scan_job_runner = ScanJobRunner()
    return scan_job_runner
