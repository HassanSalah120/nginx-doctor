"""Model package - Core data structures for nginx-doctor."""

from nginx_doctor.model.evidence import Evidence, Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import (
    LocationBlock,
    NginxInfo,
    OSInfo,
    PHPInfo,
    ProjectInfo,
    ProjectType,
    ServerBlock,
    ServerModel,
)

__all__ = [
    "Evidence",
    "Finding",
    "LocationBlock",
    "NginxInfo",
    "OSInfo",
    "PHPInfo",
    "ProjectInfo",
    "ProjectType",
    "ServerBlock",
    "ServerModel",
    "Severity",
]
