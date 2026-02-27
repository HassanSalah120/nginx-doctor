"""
FastAPI Application for nginx-doctor Project Setup Wizard.

Runs on localhost only (127.0.0.1) for security.
Provides web UI for configuring Nginx projects via SSH.
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
from nginx_doctor.web.session import session_store

# Module paths
WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
TEMPLATES_DIR = WEB_DIR / "templates"


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="nginx-doctor Wizard",
        description="Project Setup Wizard for Nginx configurations",
        version="1.0.0",
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

    @app.get("/wizard", response_class=HTMLResponse)
    async def wizard_page(request: Request) -> Any:
        """Render the main wizard page."""
        return templates.TemplateResponse("wizard.html", {"request": request})

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request) -> Any:
        """Redirect to wizard."""
        return templates.TemplateResponse("wizard.html", {"request": request})

    @app.get("/status", response_class=HTMLResponse)
    async def status_page(request: Request) -> Any:
        """Render the status dashboard."""
        return templates.TemplateResponse("status.html", {"request": request})

    @app.on_event("shutdown")
    async def cleanup() -> None:
        """Cleanup SSH sessions on shutdown."""
        session_store.cleanup_all()

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
