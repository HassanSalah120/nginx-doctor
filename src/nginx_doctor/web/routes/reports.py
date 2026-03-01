"""Report and findings API routes.

Endpoints:
    GET /api/reports/{job_id} - Full report (findings + diagnosis + score)
    GET /api/findings         - Query findings (?severity=high&job_id=X)
"""

import json
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from nginx_doctor.storage.repositories import (
    FindingRepository,
    ScanJobRepository,
)

router = APIRouter()
_job_repo = ScanJobRepository()
_finding_repo = FindingRepository()


@router.get("/reports/{job_id}")
async def get_report(job_id: int) -> dict:
    """Get full report for a completed scan job.

    Includes findings, score, and AI diagnosis.
    """
    job = _job_repo.get_by_id(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status not in ("success", "failed"):
        return {
            "job": job.to_dict(),
            "findings": [],
            "diagnosis": None,
            "message": f"Job is still {job.status}",
        }

    findings = _finding_repo.get_by_job_id(job_id)

    # Parse diagnosis JSON if available
    diagnosis = None
    if job.diagnosis_json:
        try:
            diagnosis = json.loads(job.diagnosis_json)
        except (json.JSONDecodeError, TypeError):
            pass

    return {
        "job": job.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "diagnosis": diagnosis,
    }


@router.get("/findings")
async def query_findings(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    job_id: Optional[int] = Query(None, description="Filter by job ID"),
) -> dict:
    """Query findings with optional filters."""
    if severity and job_id:
        findings = _finding_repo.get_by_severity(severity, job_id=job_id)
    elif severity:
        findings = _finding_repo.get_by_severity(severity)
    elif job_id:
        findings = _finding_repo.get_by_job_id(job_id)
    else:
        # Return recent findings (last 100)
        from nginx_doctor.storage.db import get_db

        db = get_db()
        rows = db.execute(
            "SELECT * FROM findings ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
        findings = [
            FindingRepository._row_to_record(row)  # type: ignore[arg-type]
            for row in rows
        ]

    return {"findings": [f.to_dict() for f in findings]}
