"""Server management API routes.

Endpoints:
    POST /api/servers      - Create a server
    GET  /api/servers      - List all servers
    GET  /api/servers/{id} - Get server details
"""

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from nginx_doctor.storage.repositories import ServerRepository

router = APIRouter()
_repo = ServerRepository()


class CreateServerRequest(BaseModel):
    """Request body for creating a server."""

    name: str = Field(..., description="Display name for the server")
    host: str = Field(..., description="Server hostname or IP")
    port: int = Field(22, description="SSH port")
    username: str = Field("root", description="SSH username")
    password: Optional[str] = Field(None, description="SSH password (if not using key)")
    key_path: Optional[str] = Field(None, description="Path to SSH private key")
    tags: str = Field("", description="Comma-separated tags")


@router.post("/servers")
async def create_server(request: CreateServerRequest) -> dict:
    """Register a new server."""
    server_id = _repo.create(
        name=request.name,
        host=request.host,
        port=request.port,
        username=request.username,
        password=request.password,
        key_path=request.key_path,
        tags=request.tags,
    )
    server = _repo.get_by_id(server_id)
    if not server:
        raise HTTPException(status_code=500, detail="Failed to create server")
    return {"server": server.to_dict()}


@router.get("/servers")
async def list_servers() -> dict:
    """List all registered servers."""
    servers = _repo.get_all()
    return {"servers": [s.to_dict() for s in servers]}


@router.get("/servers/{server_id}")
async def get_server(server_id: int) -> dict:
    """Get a server by ID."""
    server = _repo.get_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return {"server": server.to_dict()}
