"""Analyzer package - Analysis modules that reason about the server model.

IMPORTANT: Analyzers NEVER run shell commands.
They only reason about data already collected by scanners.
"""

from nginx_doctor.analyzer.app_detector import AppDetector
from nginx_doctor.analyzer.certbot_auditor import CertbotAuditor
from nginx_doctor.analyzer.firewall_auditor import FirewallAuditor
from nginx_doctor.analyzer.mysql_auditor import MySQLAuditor
from nginx_doctor.analyzer.network_surface_auditor import NetworkSurfaceAuditor
from nginx_doctor.analyzer.nginx_doctor import NginxDoctorAnalyzer
from nginx_doctor.analyzer.path_conflict_auditor import PathConflictAuditor
from nginx_doctor.analyzer.runtime_drift_auditor import RuntimeDriftAuditor
from nginx_doctor.analyzer.security_baseline_auditor import SecurityBaselineAuditor
from nginx_doctor.analyzer.server_auditor import ServerAuditor
from nginx_doctor.analyzer.telemetry_auditor import TelemetryAuditor
from nginx_doctor.analyzer.vulnerability_auditor import VulnerabilityAuditor

__all__ = [
    "AppDetector",
    "CertbotAuditor",
    "FirewallAuditor",
    "MySQLAuditor",
    "NetworkSurfaceAuditor",
    "NginxDoctorAnalyzer",
    "PathConflictAuditor",
    "RuntimeDriftAuditor",
    "SecurityBaselineAuditor",
    "ServerAuditor",
    "TelemetryAuditor",
    "VulnerabilityAuditor",
]
