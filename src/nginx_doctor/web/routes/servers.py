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


class UpdateServerRequest(BaseModel):
    """Request body for updating a server."""

    name: Optional[str] = Field(None, description="Display name for the server")
    host: Optional[str] = Field(None, description="Server hostname or IP")
    port: Optional[int] = Field(None, description="SSH port")
    username: Optional[str] = Field(None, description="SSH username")
    password: Optional[str] = Field(None, description="SSH password (set null to clear)")
    key_path: Optional[str] = Field(None, description="Path to SSH private key (set null to clear)")
    tags: Optional[str] = Field(None, description="Comma-separated tags")


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


@router.put("/servers/{server_id}")
async def update_server(server_id: int, request: UpdateServerRequest) -> dict:
    """Update an existing server."""
    server = _repo.get_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    fields_set = getattr(request, "model_fields_set", None)
    if fields_set is None:
        fields_set = getattr(request, "__fields_set__", set())

    update_kwargs: dict = {
        "name": request.name,
        "host": request.host,
        "port": request.port,
        "username": request.username,
        "tags": request.tags,
    }
    if "password" in fields_set:
        update_kwargs["password"] = request.password
    if "key_path" in fields_set:
        update_kwargs["key_path"] = request.key_path

    updated = _repo.update(server_id, **update_kwargs)
    if not updated:
        raise HTTPException(status_code=400, detail="No fields updated")

    fresh = _repo.get_by_id(server_id)
    if not fresh:
        raise HTTPException(status_code=500, detail="Failed to load updated server")
    return {"server": fresh.to_dict()}


@router.delete("/servers/{server_id}")
async def delete_server(server_id: int) -> dict:
    """Delete a server."""
    deleted = _repo.delete(server_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Server not found")
    return {"deleted": True}
