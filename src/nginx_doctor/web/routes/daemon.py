"""Daemon monitoring routes for nginx-doctor web app.

Provides web API for continuous monitoring daemon control.
"""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from nginx_doctor.daemon.monitor import MonitoringDaemon
from nginx_doctor.config import ConfigManager
from nginx_doctor.storage.repositories import ServerRepository

router = APIRouter(prefix="/daemon", tags=["daemon"])


class DaemonStartRequest(BaseModel):
    """Request to start monitoring daemon."""
    interval: int = Field(default=3600, ge=60, le=86400, description="Scan interval in seconds")
    server_ids: list[int] = Field(default=[], description="Server IDs to monitor (empty = all)")
    notification_enabled: bool = True


class DaemonStatusResponse(BaseModel):
    """Daemon status response."""
    running: bool
    pid: int | None
    started_at: str | None
    interval: int
    servers: list[int]
    last_scan: str | None
    next_scan: str | None
    scan_count: int
    error_count: int


class DaemonConfig(BaseModel):
    """Daemon configuration."""
    interval: int = 3600
    auto_start: bool = False
    notify_on_critical: bool = True
    notify_on_warning: bool = False
    max_retries: int = 3


# Global daemon instance
daemon_instance: MonitoringDaemon | None = None


@router.post("/start")
async def start_daemon(request: DaemonStartRequest) -> dict[str, Any]:
    """Start the monitoring daemon."""
    global daemon_instance
    
    if daemon_instance and daemon_instance.is_running():
        raise HTTPException(status_code=400, detail="Daemon already running")
    
    # Get server names from IDs
    config_mgr = ConfigManager()
    server_names = None
    if request.server_ids:
        server_repo = ServerRepository()
        servers = [server_repo.get_by_id(sid) for sid in request.server_ids]
        server_names = [s.name for s in servers if s]
    
    daemon_instance = MonitoringDaemon(
        config_mgr=config_mgr,
        interval=request.interval,
        servers=server_names,
        pid_file="/tmp/nginx-doctor-web.pid",
    )
    
    # Start in background (non-blocking for web)
    import threading
    def run_daemon():
        try:
            daemon_instance.start()
        except Exception as e:
            print(f"Daemon error: {e}")
    
    thread = threading.Thread(target=run_daemon, daemon=True)
    thread.start()
    
    return {
        "status": "started",
        "interval": request.interval,
        "servers": request.server_ids,
        "pid_file": "/tmp/nginx-doctor-web.pid",
    }


@router.post("/stop")
async def stop_daemon() -> dict[str, Any]:
    """Stop the monitoring daemon."""
    global daemon_instance
    
    if daemon_instance:
        daemon_instance.stop()
        daemon_instance = None
    
    # Also check PID file
    daemon = MonitoringDaemon(pid_file="/tmp/nginx-doctor-web.pid")
    if daemon.is_running():
        daemon.stop()
    
    return {"status": "stopped"}


@router.get("/status", response_model=DaemonStatusResponse)
async def get_daemon_status() -> DaemonStatusResponse:
    """Get daemon status."""
    global daemon_instance
    
    # Check both global instance and PID file
    daemon = daemon_instance or MonitoringDaemon(pid_file="/tmp/nginx-doctor-web.pid")
    
    running = daemon.is_running()
    info = daemon.get_info() if running else {}
    
    return DaemonStatusResponse(
        running=running,
        pid=info.get("pid"),
        started_at=None,  # Could be enhanced to track this
        interval=info.get("interval", 3600),
        servers=[],  # Could be enhanced to track this
        last_scan=None,  # Could be enhanced to track this
        next_scan=None,
        scan_count=0,
        error_count=0,
    )


@router.get("/config")
async def get_daemon_config() -> DaemonConfig:
    """Get daemon configuration."""
    config_mgr = ConfigManager()
    config = config_mgr.get_notification("daemon") or {}
    
    return DaemonConfig(
        interval=config.get("interval", 3600),
        auto_start=config.get("auto_start", False),
        notify_on_critical=config.get("notify_on_critical", True),
        notify_on_warning=config.get("notify_on_warning", False),
        max_retries=config.get("max_retries", 3),
    )


@router.post("/config")
async def update_daemon_config(config: DaemonConfig) -> DaemonConfig:
    """Update daemon configuration."""
    config_mgr = ConfigManager()
    config_mgr.set_notification("daemon", config.dict())
    
    return config


@router.get("/history")
async def get_scan_history(limit: int = 10) -> list[dict[str, Any]]:
    """Get recent scan history from daemon."""
    # This would track daemon scan history
    # For now, return placeholder
    return []


@router.post("/scan-now")
async def trigger_manual_scan(server_ids: list[int] = []) -> dict[str, Any]:
    """Trigger immediate scan via daemon."""
    global daemon_instance
    
    if not daemon_instance or not daemon_instance.is_running():
        raise HTTPException(status_code=400, detail="Daemon not running")
    
    # Trigger one scan cycle
    import threading
    def trigger():
        daemon_instance._run_scan_cycle()
    
    thread = threading.Thread(target=trigger)
    thread.start()
    
    return {
        "status": "scan_triggered",
        "servers": server_ids,
        "timestamp": datetime.utcnow().isoformat(),
    }
