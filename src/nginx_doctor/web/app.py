"""
FastAPI Application for NginxDoctor — AI Infrastructure Diagnosis Platform.

Runs on localhost only (127.0.0.1) for security.
Provides web UI for infrastructure scanning, diagnosis, and report viewing.
"""

import secrets
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from nginx_doctor.web.routes import connect, preview, apply, jobs, status
from nginx_doctor.web.routes import servers as servers_route
from nginx_doctor.web.routes import scans as scans_route
from nginx_doctor.web.routes import reports as reports_route
from nginx_doctor.web.session import session_store

# Module paths
WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
TEMPLATES_DIR = WEB_DIR / "templates"


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="NginxDoctor — AI Infrastructure Diagnosis Platform",
        description="Local web-based DevOps tool for scanning, diagnosing, and reporting infrastructure health",
        version="2.0.0",
        docs_url="/api/docs",
        redoc_url=None,
    )

    # CORS - restrict to localhost only
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:*", "http://localhost:*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # Templates
    templates = Jinja2Templates(directory=TEMPLATES_DIR)

    # Include API routers
    app.include_router(connect.router, prefix="/api", tags=["connection"])
    app.include_router(preview.router, prefix="/api", tags=["preview"])
    app.include_router(apply.router, prefix="/api", tags=["apply"])
    app.include_router(jobs.router, prefix="/api", tags=["jobs"])
    app.include_router(status.router, prefix="/api", tags=["status"])

    # New API routers for the diagnosis platform
    app.include_router(servers_route.router, prefix="/api", tags=["servers"])
    app.include_router(scans_route.router, prefix="/api", tags=["scans"])
    app.include_router(reports_route.router, prefix="/api", tags=["reports"])

    @app.get("/wizard", response_class=HTMLResponse)
    async def wizard_page(request: Request) -> Any:
        """Render the main wizard page."""
        return templates.TemplateResponse("wizard.html", {"request": request})

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request) -> Any:
        """Dashboard — main landing page."""
        return templates.TemplateResponse("dashboard.html", {"request": request})

    @app.get("/servers", response_class=HTMLResponse)
    async def servers_page(request: Request) -> Any:
        """Server management page."""
        return templates.TemplateResponse("servers.html", {"request": request})

    @app.get("/jobs", response_class=HTMLResponse)
    async def jobs_page(request: Request) -> Any:
        """Scan jobs list page."""
        return templates.TemplateResponse("jobs.html", {"request": request})

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    async def job_detail_page(request: Request, job_id: int) -> Any:
        """Individual job detail and live log page."""
        return templates.TemplateResponse(
            "job_detail.html", {"request": request, "job_id": job_id}
        )

    @app.get("/reports/{job_id}", response_class=HTMLResponse)
    async def report_page(request: Request, job_id: int) -> Any:
        """Scan report page."""
        return templates.TemplateResponse(
            "report.html", {"request": request, "job_id": job_id}
        )

    @app.on_event("startup")
    async def startup() -> None:
        """Initialize database and job runner on startup."""
        from nginx_doctor.storage import init_db
        init_db()
        from nginx_doctor.web.job_runner import get_runner
        get_runner()  # Initialize the singleton

    @app.on_event("shutdown")
    async def cleanup() -> None:
        """Cleanup SSH sessions and job runner on shutdown."""
        session_store.cleanup_all()
        from nginx_doctor.web.job_runner import scan_job_runner
        if scan_job_runner:
            scan_job_runner.shutdown(wait=False)

    return app


def run_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Run the FastAPI server with uvicorn.
    
    Args:
        host: Bind address. MUST be 127.0.0.1 for security.
        port: Port to listen on.
    """
    import uvicorn
    
    # Security: Force localhost binding
    if host != "127.0.0.1":
        print("⚠️  Security: Forcing bind to 127.0.0.1 (localhost only)")
        host = "127.0.0.1"
    
    print(f"🚀 Starting nginx-doctor wizard at http://{host}:{port}/wizard")
    uvicorn.run(create_app(), host=host, port=port, log_level="info")


# Global app instance for uvicorn
app = create_app()
