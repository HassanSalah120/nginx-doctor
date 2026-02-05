"""Analyzer package - Analysis modules that reason about the server model.

IMPORTANT: Analyzers NEVER run shell commands.
They only reason about data already collected by scanners.
"""

from nginx_doctor.analyzer.app_detector import AppDetector
from nginx_doctor.analyzer.nginx_doctor import NginxDoctorAnalyzer
from nginx_doctor.analyzer.server_auditor import ServerAuditor

__all__ = ["AppDetector", "NginxDoctorAnalyzer", "ServerAuditor"]
