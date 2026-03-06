"""Analyzer package - Analysis modules that reason about the server model.

IMPORTANT: Analyzers NEVER run shell commands.
They only reason about data already collected by scanners.
"""

from nginx_doctor.analyzer.app_detector import AppDetector
from nginx_doctor.analyzer.certbot_auditor import CertbotAuditor
from nginx_doctor.analyzer.firewall_auditor import FirewallAuditor
from nginx_doctor.analyzer.kernel_limits_auditor import KernelLimitsAuditor
from nginx_doctor.analyzer.logs_auditor import LogsAuditor
from nginx_doctor.analyzer.mysql_auditor import MySQLAuditor
from nginx_doctor.analyzer.network_surface_auditor import NetworkSurfaceAuditor
from nginx_doctor.analyzer.nginx_doctor import NginxDoctorAnalyzer
from nginx_doctor.analyzer.path_conflict_auditor import PathConflictAuditor
from nginx_doctor.analyzer.ops_posture_auditor import OpsPostureAuditor
from nginx_doctor.analyzer.resources_auditor import ResourcesAuditor
from nginx_doctor.analyzer.runtime_drift_auditor import RuntimeDriftAuditor
from nginx_doctor.analyzer.security_baseline_auditor import SecurityBaselineAuditor
from nginx_doctor.analyzer.server_auditor import ServerAuditor
from nginx_doctor.analyzer.storage_auditor import StorageAuditor
from nginx_doctor.analyzer.telemetry_auditor import TelemetryAuditor
from nginx_doctor.analyzer.vulnerability_auditor import VulnerabilityAuditor

__all__ = [
    "AppDetector",
    "CertbotAuditor",
    "FirewallAuditor",
    "KernelLimitsAuditor",
    "LogsAuditor",
    "MySQLAuditor",
    "NetworkSurfaceAuditor",
    "NginxDoctorAnalyzer",
    "PathConflictAuditor",
    "OpsPostureAuditor",
    "ResourcesAuditor",
    "RuntimeDriftAuditor",
    "SecurityBaselineAuditor",
    "ServerAuditor",
    "StorageAuditor",
    "TelemetryAuditor",
    "VulnerabilityAuditor",
]
