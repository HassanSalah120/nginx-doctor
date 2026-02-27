"""
Jobs API routes.

Endpoint:
- GET /api/jobs/{job_id} - Poll job status and logs
"""

from pydantic import BaseModel, Field
from typing import Any

from fastapi import APIRouter, HTTPException

from nginx_doctor.web.jobs import job_executor


router = APIRouter()


class JobLogEntry(BaseModel):
    """Log entry in job."""
    timestamp: str
    level: str
    message: str


class JobResponse(BaseModel):
    """Job status response."""
    id: str
    status: str
    logs: list[JobLogEntry]
    result: dict[str, Any]
    created_at: str
    started_at: str | None
    completed_at: str | None


@router.get("/jobs/{job_id}", response_model=JobResponse)
async def get_job_status(job_id: str) -> JobResponse:
    """Get job status and logs.
    
    Poll this endpoint to track job progress.
    """
    job = job_executor.get_job(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job_dict = job.to_dict()
    
    return JobResponse(
        id=job_dict["id"],
        status=job_dict["status"],
        logs=[JobLogEntry(**log) for log in job_dict["logs"]],
        result=job_dict["result"],
        created_at=job_dict["created_at"],
        started_at=job_dict["started_at"],
        completed_at=job_dict["completed_at"],
    )
