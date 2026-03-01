"""Tests for CLI Flags.

Verifies:
1. --score triggers Score output.
2. --explain triggers Explanations.
3. --safe-fix triggers SafeFixAction.
4. Default behavior remains backward compatible.
"""

from unittest.mock import MagicMock, patch
from click.testing import CliRunner
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from nginx_doctor.cli import diagnose, _scan_time_label, _resolve_html_output_path

def test_score_flag():
    """Verify --score passes true to ReportAction."""
    runner = CliRunner()
    
    with patch("nginx_doctor.cli._resolve_config") as mock_resolve, \
         patch("nginx_doctor.cli._scan_server") as mock_scan, \
         patch("nginx_doctor.cli.SSHConnector"), \
         patch("nginx_doctor.cli.NginxDoctorAnalyzer") as mock_dr, \
         patch("nginx_doctor.cli.ServerAuditor") as mock_auditor, \
         patch("nginx_doctor.analyzer.wss_auditor.WSSAuditor") as mock_wss, \
         patch("nginx_doctor.analyzer.docker_auditor.DockerAuditor") as mock_docker, \
         patch("nginx_doctor.analyzer.node_auditor.NodeAuditor") as mock_node, \
         patch("nginx_doctor.analyzer.systemd_auditor.SystemdAuditor") as mock_systemd, \
         patch("nginx_doctor.analyzer.redis_auditor.RedisAuditor") as mock_redis, \
         patch("nginx_doctor.analyzer.worker_auditor.WorkerAuditor") as mock_worker, \
         patch("nginx_doctor.analyzer.mysql_auditor.MySQLAuditor") as mock_mysql, \
         patch("nginx_doctor.analyzer.firewall_auditor.FirewallAuditor") as mock_firewall, \
         patch("nginx_doctor.analyzer.telemetry_auditor.TelemetryAuditor") as mock_telemetry, \
         patch("nginx_doctor.analyzer.security_baseline_auditor.SecurityBaselineAuditor") as mock_baseline, \
         patch("nginx_doctor.analyzer.vulnerability_auditor.VulnerabilityAuditor") as mock_vulnerability, \
         patch("nginx_doctor.analyzer.network_surface_auditor.NetworkSurfaceAuditor") as mock_network_surface, \
         patch("nginx_doctor.checks.run_checks") as mock_run, \
         patch("nginx_doctor.cli.ReportAction") as MockReporter:
        
        from nginx_doctor.model.server import ServerModel, NginxInfo, PHPInfo, ServiceStatus, CapabilityLevel
        mock_resolve.return_value = MagicMock()
        mock_scan.return_value = ServerModel(
            hostname="test", 
            nginx=NginxInfo(version="1.24.0", config_path="/etc/nginx/nginx.conf"), 
            php=PHPInfo(versions=[]), 
            nginx_status=ServiceStatus(capability=CapabilityLevel.FULL)
        )
        mock_dr.return_value.diagnose.return_value = []
        mock_auditor.return_value.audit.return_value = []
        mock_wss.return_value.audit.return_value = []
        mock_wss.return_value.get_inventory.return_value = []
        for mocked in [mock_docker, mock_node, mock_systemd, mock_redis, mock_worker, mock_mysql, mock_firewall, mock_telemetry, mock_baseline, mock_vulnerability, mock_network_surface]:
            mocked.return_value.audit.return_value = []
        mock_run.return_value = []
        
        result = runner.invoke(diagnose, ["myserver", "--score", "--format", "rich"])
        
        assert result.exit_code == 0
        assert MockReporter.called
        _, kwargs = MockReporter.call_args
        assert kwargs.get("show_score") is True

def test_explain_flag():
    """Verify --explain passes true to ReportAction."""
    runner = CliRunner()
    
    with patch("nginx_doctor.cli._resolve_config") as mock_resolve, \
         patch("nginx_doctor.cli._scan_server") as mock_scan, \
         patch("nginx_doctor.cli.SSHConnector"), \
         patch("nginx_doctor.cli.NginxDoctorAnalyzer") as mock_dr, \
         patch("nginx_doctor.cli.ServerAuditor") as mock_auditor, \
         patch("nginx_doctor.analyzer.wss_auditor.WSSAuditor") as mock_wss, \
         patch("nginx_doctor.analyzer.docker_auditor.DockerAuditor") as mock_docker, \
         patch("nginx_doctor.analyzer.node_auditor.NodeAuditor") as mock_node, \
         patch("nginx_doctor.analyzer.systemd_auditor.SystemdAuditor") as mock_systemd, \
         patch("nginx_doctor.analyzer.redis_auditor.RedisAuditor") as mock_redis, \
         patch("nginx_doctor.analyzer.worker_auditor.WorkerAuditor") as mock_worker, \
         patch("nginx_doctor.analyzer.mysql_auditor.MySQLAuditor") as mock_mysql, \
         patch("nginx_doctor.analyzer.firewall_auditor.FirewallAuditor") as mock_firewall, \
         patch("nginx_doctor.analyzer.telemetry_auditor.TelemetryAuditor") as mock_telemetry, \
         patch("nginx_doctor.analyzer.security_baseline_auditor.SecurityBaselineAuditor") as mock_baseline, \
         patch("nginx_doctor.analyzer.vulnerability_auditor.VulnerabilityAuditor") as mock_vulnerability, \
         patch("nginx_doctor.analyzer.network_surface_auditor.NetworkSurfaceAuditor") as mock_network_surface, \
         patch("nginx_doctor.checks.run_checks") as mock_run, \
         patch("nginx_doctor.cli.ReportAction") as MockReporter:
        
        from nginx_doctor.model.server import ServerModel, NginxInfo, PHPInfo, ServiceStatus, CapabilityLevel
        mock_resolve.return_value = MagicMock()
        mock_scan.return_value = ServerModel(
            hostname="test", 
            nginx=NginxInfo(version="1.24.0", config_path="/etc/nginx/nginx.conf"), 
            php=PHPInfo(versions=[]), 
            nginx_status=ServiceStatus(capability=CapabilityLevel.FULL)
        )
        mock_dr.return_value.diagnose.return_value = []
        mock_auditor.return_value.audit.return_value = []
        mock_wss.return_value.audit.return_value = []
        mock_wss.return_value.get_inventory.return_value = []
        for mocked in [mock_docker, mock_node, mock_systemd, mock_redis, mock_worker, mock_mysql, mock_firewall, mock_telemetry, mock_baseline, mock_vulnerability, mock_network_surface]:
            mocked.return_value.audit.return_value = []
        mock_run.return_value = []
        
        result = runner.invoke(diagnose, ["myserver", "--explain", "--format", "rich"])
        
        assert result.exit_code == 0
        assert MockReporter.called
        _, kwargs = MockReporter.call_args
        assert kwargs.get("show_explain") is True

def test_safe_fix_trigger():
    """Verify --safe-fix triggers SafeFixAction."""
    runner = CliRunner()
    
    with patch("nginx_doctor.cli._resolve_config") as mock_resolve, \
         patch("nginx_doctor.cli._scan_server") as mock_scan, \
         patch("nginx_doctor.cli.SSHConnector"), \
         patch("nginx_doctor.cli.NginxDoctorAnalyzer") as mock_dr, \
         patch("nginx_doctor.cli.ServerAuditor") as mock_auditor, \
         patch("nginx_doctor.analyzer.wss_auditor.WSSAuditor") as mock_wss, \
         patch("nginx_doctor.analyzer.docker_auditor.DockerAuditor") as mock_docker, \
         patch("nginx_doctor.analyzer.node_auditor.NodeAuditor") as mock_node, \
         patch("nginx_doctor.analyzer.systemd_auditor.SystemdAuditor") as mock_systemd, \
         patch("nginx_doctor.analyzer.redis_auditor.RedisAuditor") as mock_redis, \
         patch("nginx_doctor.analyzer.worker_auditor.WorkerAuditor") as mock_worker, \
         patch("nginx_doctor.analyzer.mysql_auditor.MySQLAuditor") as mock_mysql, \
         patch("nginx_doctor.analyzer.firewall_auditor.FirewallAuditor") as mock_firewall, \
         patch("nginx_doctor.analyzer.telemetry_auditor.TelemetryAuditor") as mock_telemetry, \
         patch("nginx_doctor.analyzer.security_baseline_auditor.SecurityBaselineAuditor") as mock_baseline, \
         patch("nginx_doctor.analyzer.vulnerability_auditor.VulnerabilityAuditor") as mock_vulnerability, \
         patch("nginx_doctor.analyzer.network_surface_auditor.NetworkSurfaceAuditor") as mock_network_surface, \
         patch("nginx_doctor.checks.run_checks") as mock_run_checks, \
         patch("nginx_doctor.cli.ReportAction") as mock_report, \
         patch("nginx_doctor.cli.SafeFixAction") as MockFixer:
        
        from nginx_doctor.model.server import ServerModel, NginxInfo, PHPInfo, ServiceStatus, CapabilityLevel
        mock_resolve.return_value = MagicMock()
        mock_scan.return_value = ServerModel(
            hostname="test", 
            nginx=NginxInfo(version="1.24.0", config_path="/etc/nginx/nginx.conf"), 
            php=PHPInfo(versions=[]), 
            nginx_status=ServiceStatus(capability=CapabilityLevel.FULL)
        )
        mock_dr.return_value.diagnose.return_value = []
        mock_auditor.return_value.audit.return_value = []
        mock_wss.return_value.audit.return_value = []
        mock_wss.return_value.get_inventory.return_value = []
        for mocked in [mock_docker, mock_node, mock_systemd, mock_redis, mock_worker, mock_mysql, mock_firewall, mock_telemetry, mock_baseline, mock_vulnerability, mock_network_surface]:
            mocked.return_value.audit.return_value = []
        mock_report.return_value.report_findings.return_value = 0
        
        from nginx_doctor.model.finding import Finding
        from nginx_doctor.model.evidence import Severity, Evidence
        mock_run_checks.return_value = [Finding(
            id="TEST-1", severity=Severity.INFO, confidence=1.0, 
            condition="test", cause="test", treatment="test", impact=["test"],
            evidence=[Evidence(source_file="test", line_number=1, excerpt="test")]
        )]
        
        MockFixer.return_value.run.return_value = []
        
        result = runner.invoke(diagnose, ["myserver", "--safe-fix", "--dry-run", "--format", "rich"], obj={})
        
        assert result.exit_code == 0
        MockFixer.assert_called()
        MockFixer.return_value.run.assert_called()


def test_optional_checks_enabled_by_default():
    """Diagnose should run modular checks by default unless --minimal is set."""
    runner = CliRunner()

    with patch("nginx_doctor.cli._resolve_config") as mock_resolve, \
         patch("nginx_doctor.cli._scan_server") as mock_scan, \
         patch("nginx_doctor.cli.SSHConnector"), \
         patch("nginx_doctor.cli.NginxDoctorAnalyzer") as mock_dr, \
         patch("nginx_doctor.cli.ServerAuditor") as mock_server_auditor, \
         patch("nginx_doctor.analyzer.wss_auditor.WSSAuditor") as mock_wss, \
         patch("nginx_doctor.analyzer.docker_auditor.DockerAuditor") as mock_docker, \
         patch("nginx_doctor.analyzer.node_auditor.NodeAuditor") as mock_node, \
         patch("nginx_doctor.analyzer.systemd_auditor.SystemdAuditor") as mock_systemd, \
         patch("nginx_doctor.analyzer.redis_auditor.RedisAuditor") as mock_redis, \
         patch("nginx_doctor.analyzer.worker_auditor.WorkerAuditor") as mock_worker, \
         patch("nginx_doctor.analyzer.mysql_auditor.MySQLAuditor") as mock_mysql, \
         patch("nginx_doctor.analyzer.firewall_auditor.FirewallAuditor") as mock_firewall, \
         patch("nginx_doctor.analyzer.telemetry_auditor.TelemetryAuditor") as mock_telemetry, \
         patch("nginx_doctor.analyzer.security_baseline_auditor.SecurityBaselineAuditor") as mock_baseline, \
         patch("nginx_doctor.analyzer.vulnerability_auditor.VulnerabilityAuditor") as mock_vulnerability, \
         patch("nginx_doctor.analyzer.network_surface_auditor.NetworkSurfaceAuditor") as mock_network_surface, \
         patch("nginx_doctor.checks.run_checks") as mock_run:

        mock_resolve.return_value = MagicMock()
        mock_scan.return_value = MagicMock()
        mock_dr.return_value.diagnose.return_value = []
        for mocked in [mock_server_auditor, mock_wss, mock_docker, mock_node, mock_systemd, mock_redis, mock_worker, mock_mysql, mock_firewall, mock_telemetry, mock_baseline, mock_vulnerability, mock_network_surface]:
            mocked.return_value.audit.return_value = []
        mock_wss.return_value.get_inventory.return_value = []
        mock_run.return_value = []

        result = runner.invoke(diagnose, ["myserver", "--format", "rich"])
        assert result.exit_code == 0

        ctx = mock_run.call_args.args[0]
        assert ctx.laravel_enabled is True
        assert ctx.ports_enabled is True
        assert ctx.security_enabled is True
        assert ctx.phpfpm_enabled is True
        assert ctx.performance_enabled is True


def test_minimal_mode_allows_selective_opt_in():
    """--minimal should disable optional checks unless explicitly enabled."""
    runner = CliRunner()

    with patch("nginx_doctor.cli._resolve_config") as mock_resolve, \
         patch("nginx_doctor.cli._scan_server") as mock_scan, \
         patch("nginx_doctor.cli.SSHConnector"), \
         patch("nginx_doctor.cli.NginxDoctorAnalyzer") as mock_dr, \
         patch("nginx_doctor.cli.ServerAuditor") as mock_server_auditor, \
         patch("nginx_doctor.analyzer.wss_auditor.WSSAuditor") as mock_wss, \
         patch("nginx_doctor.analyzer.docker_auditor.DockerAuditor") as mock_docker, \
         patch("nginx_doctor.analyzer.node_auditor.NodeAuditor") as mock_node, \
         patch("nginx_doctor.analyzer.systemd_auditor.SystemdAuditor") as mock_systemd, \
         patch("nginx_doctor.analyzer.redis_auditor.RedisAuditor") as mock_redis, \
         patch("nginx_doctor.analyzer.worker_auditor.WorkerAuditor") as mock_worker, \
         patch("nginx_doctor.analyzer.mysql_auditor.MySQLAuditor") as mock_mysql, \
         patch("nginx_doctor.analyzer.firewall_auditor.FirewallAuditor") as mock_firewall, \
         patch("nginx_doctor.analyzer.telemetry_auditor.TelemetryAuditor") as mock_telemetry, \
         patch("nginx_doctor.analyzer.security_baseline_auditor.SecurityBaselineAuditor") as mock_baseline, \
         patch("nginx_doctor.analyzer.vulnerability_auditor.VulnerabilityAuditor") as mock_vulnerability, \
         patch("nginx_doctor.analyzer.network_surface_auditor.NetworkSurfaceAuditor") as mock_network_surface, \
         patch("nginx_doctor.checks.run_checks") as mock_run:

        mock_resolve.return_value = MagicMock()
        mock_scan.return_value = MagicMock()
        mock_dr.return_value.diagnose.return_value = []
        for mocked in [mock_server_auditor, mock_wss, mock_docker, mock_node, mock_systemd, mock_redis, mock_worker, mock_mysql, mock_firewall, mock_telemetry, mock_baseline, mock_vulnerability, mock_network_surface]:
            mocked.return_value.audit.return_value = []
        mock_wss.return_value.get_inventory.return_value = []
        mock_run.return_value = []

        result = runner.invoke(diagnose, ["myserver", "--minimal", "--ports", "--format", "rich"])
        assert result.exit_code == 0

        ctx = mock_run.call_args.args[0]
        assert ctx.laravel_enabled is False
        assert ctx.ports_enabled is True
        assert ctx.security_enabled is False
        assert ctx.phpfpm_enabled is False
        assert ctx.performance_enabled is False


def test_diagnose_defaults_to_html_output():
    """Diagnose should default to HTML report mode when no format/interactive flags are set."""
    runner = CliRunner()

    with patch("nginx_doctor.cli._resolve_config") as mock_resolve, \
         patch("nginx_doctor.cli._scan_server") as mock_scan, \
         patch("nginx_doctor.cli.SSHConnector"), \
         patch("nginx_doctor.cli.NginxDoctorAnalyzer") as mock_dr, \
         patch("nginx_doctor.cli.ServerAuditor") as mock_server_auditor, \
         patch("nginx_doctor.analyzer.wss_auditor.WSSAuditor") as mock_wss, \
         patch("nginx_doctor.analyzer.docker_auditor.DockerAuditor") as mock_docker, \
         patch("nginx_doctor.analyzer.node_auditor.NodeAuditor") as mock_node, \
         patch("nginx_doctor.analyzer.systemd_auditor.SystemdAuditor") as mock_systemd, \
         patch("nginx_doctor.analyzer.redis_auditor.RedisAuditor") as mock_redis, \
         patch("nginx_doctor.analyzer.worker_auditor.WorkerAuditor") as mock_worker, \
         patch("nginx_doctor.analyzer.mysql_auditor.MySQLAuditor") as mock_mysql, \
         patch("nginx_doctor.analyzer.firewall_auditor.FirewallAuditor") as mock_firewall, \
         patch("nginx_doctor.analyzer.telemetry_auditor.TelemetryAuditor") as mock_telemetry, \
         patch("nginx_doctor.analyzer.security_baseline_auditor.SecurityBaselineAuditor") as mock_baseline, \
         patch("nginx_doctor.analyzer.vulnerability_auditor.VulnerabilityAuditor") as mock_vulnerability, \
         patch("nginx_doctor.analyzer.network_surface_auditor.NetworkSurfaceAuditor") as mock_network_surface, \
         patch("nginx_doctor.checks.run_checks") as mock_run, \
         patch("nginx_doctor.cli.HTMLReportAction") as mock_html, \
         patch("nginx_doctor.cli.ReportBundleAction") as mock_bundle:

        from nginx_doctor.model.server import CapabilityLevel, NginxInfo, PHPInfo, ServerModel, ServiceStatus

        mock_resolve.return_value = MagicMock()
        mock_scan.return_value = ServerModel(
            hostname="example.com",
            nginx=NginxInfo(version="1.24.0", config_path="/etc/nginx/nginx.conf"),
            php=PHPInfo(versions=["8.2"]),
            nginx_status=ServiceStatus(capability=CapabilityLevel.FULL),
        )
        mock_dr.return_value.diagnose.return_value = []
        for mocked in [mock_server_auditor, mock_wss, mock_docker, mock_node, mock_systemd, mock_redis, mock_worker, mock_mysql, mock_firewall, mock_telemetry, mock_baseline, mock_vulnerability, mock_network_surface]:
            mocked.return_value.audit.return_value = []
        mock_wss.return_value.get_inventory.return_value = []
        mock_run.return_value = []
        mock_html.return_value.generate.return_value = "report.html"
        mock_bundle.return_value.export.return_value = {
            "summary": "summary.txt",
            "model": "model.json",
            "findings": "findings.json",
        }

        result = runner.invoke(diagnose, ["myserver"])
        assert result.exit_code == 0
        mock_html.assert_called_once()
        mock_html.return_value.generate.assert_called_once()
        mock_bundle.assert_called_once()

        _, kwargs = mock_html.return_value.generate.call_args
        assert "reports" in kwargs.get("output_path", "")
        assert "example.com" in kwargs.get("output_path", "")


def test_scan_time_label_is_day_month_year():
    label = _scan_time_label("2026-02-11T14:45:39")
    assert label == "11-02-2026"


def test_default_html_output_path_uses_date_only_folder():
    path = _resolve_html_output_path(output=None, hostname="example.com", scan_timestamp="2026-02-11T14:45:39")
    assert str(path).endswith("reports\\example.com\\11-02-2026\\report.html")
