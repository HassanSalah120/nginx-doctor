"""Model package - Core data structures for nginx-doctor."""

from nginx_doctor.model.evidence import Evidence, Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import (
    CertbotModel,
    DiskUsage,
    LocationBlock,
    NginxInfo,
    NetworkEndpoint,
    NetworkSurfaceModel,
    OSInfo,
    PHPInfo,
    ProjectInfo,
    ProjectType,
    SecurityBaselineModel,
    ServerBlock,
    ServerModel,
    TelemetryModel,
    VulnerabilityModel,
)

__all__ = [
    "Evidence",
    "CertbotModel",
    "DiskUsage",
    "Finding",
    "LocationBlock",
    "NginxInfo",
    "NetworkEndpoint",
    "NetworkSurfaceModel",
    "OSInfo",
    "PHPInfo",
    "ProjectInfo",
    "ProjectType",
    "SecurityBaselineModel",
    "ServerBlock",
    "ServerModel",
    "Severity",
    "TelemetryModel",
    "VulnerabilityModel",
]
