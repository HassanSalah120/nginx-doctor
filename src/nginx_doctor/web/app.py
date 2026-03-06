"""
FastAPI Application for NginxDoctor — AI Infrastructure Diagnosis Platform.

Runs on localhost only (127.0.0.1) for security.
Provides web UI for infrastructure scanning, diagnosis, and report viewing.
"""

import secrets
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from nginx_doctor.web.routes import connect, preview, apply, jobs, status
from nginx_doctor.web.routes import servers as servers_route
from nginx_doctor.web.routes import scans as scans_route
from nginx_doctor.web.routes import reports as reports_route
from nginx_doctor.web.routes import cicd, daemon, notifications, k8s
from nginx_doctor.web.session import session_store

# Module paths
WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
TEMPLATES_DIR = WEB_DIR / "templates"
SPA_INDEX = STATIC_DIR / "spa" / "index.html"


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

    def _serve_spa_or_template(request: Request, template_name: str, context: dict[str, Any] | None = None) -> Any:
        if SPA_INDEX.exists():
            path = request.url.path
            if not path.startswith("/"):
                path = "/" + path
            # SPA build is served under /static/spa/ (Vite base). Redirect deep links to that base.
            target = "/static/spa" + ("/" if path == "/" else path)
            return RedirectResponse(url=target, status_code=307)
        payload: dict[str, Any] = {"request": request}
        if context:
            payload.update(context)
        return templates.TemplateResponse(template_name, payload)

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
    
    # Enterprise feature routers
    app.include_router(cicd.router, prefix="/api", tags=["ci-cd"])
    app.include_router(daemon.router, prefix="/api", tags=["daemon"])
    app.include_router(notifications.router, prefix="/api", tags=["notifications"])
    app.include_router(k8s.router, prefix="/api", tags=["kubernetes"])

    @app.get("/wizard", response_class=HTMLResponse)
    async def wizard_page(request: Request) -> Any:
        """Render the main wizard page."""
        return _serve_spa_or_template(request, "wizard.html")

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request) -> Any:
        """Dashboard — main landing page."""
        return _serve_spa_or_template(request, "dashboard.html")

    @app.get("/servers", response_class=HTMLResponse)
    async def servers_page(request: Request) -> Any:
        """Server management page."""
        return _serve_spa_or_template(request, "servers.html")

    @app.get("/jobs", response_class=HTMLResponse)
    async def jobs_page(request: Request) -> Any:
        """Scan jobs list page."""
        return _serve_spa_or_template(request, "jobs.html")

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    async def job_detail_page(request: Request, job_id: int) -> Any:
        """Individual job detail and live log page."""
        return _serve_spa_or_template(request, "job_detail.html", {"job_id": job_id})

    @app.get("/reports/{job_id}", response_class=HTMLResponse)
    async def report_page(request: Request, job_id: int) -> Any:
        """Scan report page."""
        return _serve_spa_or_template(request, "report.html", {"job_id": job_id})
    
    @app.get("/settings/integrations", response_class=HTMLResponse)
    async def integrations_page(request: Request) -> Any:
        """Integrations and notifications settings page."""
        return _serve_spa_or_template(request, "integrations.html")
    
    @app.get("/settings/daemon", response_class=HTMLResponse)
    async def daemon_settings_page(request: Request) -> Any:
        """Daemon monitoring settings page."""
        return _serve_spa_or_template(request, "daemon.html")
    
    @app.get("/kubernetes", response_class=HTMLResponse)
    async def kubernetes_page(request: Request) -> Any:
        """Kubernetes analyzer page."""
        return _serve_spa_or_template(request, "kubernetes.html")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa_fallback(request: Request, path: str) -> Any:
        if not SPA_INDEX.exists():
            raise HTTPException(status_code=404, detail="Not found")
        if path.startswith("api/") or path.startswith("static/"):
            raise HTTPException(status_code=404, detail="Not found")
        if path in ("favicon.ico",):
            raise HTTPException(status_code=404, detail="Not found")
        target = "/static/spa/" + path
        return RedirectResponse(url=target, status_code=307)

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
        print("Security: Forcing bind to 127.0.0.1 (localhost only)")
        host = "127.0.0.1"
    
    print(f"Starting nginx-doctor wizard at http://{host}:{port}/wizard")
    uvicorn.run(create_app(), host=host, port=port, log_level="info")


# Global app instance for uvicorn
app = create_app()
