"""Scan job API routes.

Endpoints:
    POST /api/scan      - Start a scan job
    GET  /api/jobs      - List all scan jobs
    GET  /api/jobs/{id} - Get job detail + logs (for live polling)
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from nginx_doctor.storage.repositories import (
    JobLogRepository,
    ScanJobRepository,
    ServerRepository,
)
from nginx_doctor.web.job_runner import get_runner

router = APIRouter()
_job_repo = ScanJobRepository()
_log_repo = JobLogRepository()
_server_repo = ServerRepository()


class ScanRequest(BaseModel):
    """Request body for starting a scan."""

    server_id: int = Field(..., description="ID of the server to scan")


@router.post("/scan")
async def start_scan(request: ScanRequest) -> dict:
    """Start a new scan job for a server."""
    # Verify server exists
    server = _server_repo.get_by_id(request.server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    try:
        runner = get_runner()
        job_id = runner.submit_scan(request.server_id)
        return {"job_id": job_id, "status": "queued"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")


@router.get("/scan/jobs")
async def list_jobs() -> dict:
    """List all scan jobs with server info."""
    jobs = _job_repo.get_all()
    return {"jobs": [j.to_dict() for j in jobs]}


@router.get("/scan/jobs/{job_id}")
async def get_job(job_id: int, after_log_id: int = 0) -> dict:
    """Get job detail with logs.

    Supports efficient polling via after_log_id parameter —
    pass the last seen log ID to only receive new entries.
    """
    job = _job_repo.get_by_id(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    logs = _log_repo.get_by_job_id(job_id, after_id=after_log_id)

    return {
        "job": job.to_dict(),
        "logs": [log.to_dict() for log in logs],
    }


@router.post("/scan/jobs/{job_id}/cancel")
async def cancel_job(job_id: int) -> dict:
    """Mark a queued or running job for cancellation."""
    job = _job_repo.get_by_id(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status not in ("queued", "running"):
        raise HTTPException(status_code=400, detail="Only queued or running jobs can be cancelled")

    _job_repo.update_status(job_id, "cancel_requested")
    _log_repo.append(job_id, "Cancellation requested by user")
    return {"status": "cancel_requested"}
