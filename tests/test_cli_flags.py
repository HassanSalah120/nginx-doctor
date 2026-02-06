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

from nginx_doctor.cli import diagnose

def test_score_flag():
    """Verify --score passes true to ReportAction."""
    runner = CliRunner()
    
    with patch("nginx_doctor.cli._resolve_config") as mock_resolve, \
         patch("nginx_doctor.cli._scan_server") as mock_scan, \
         patch("nginx_doctor.cli.SSHConnector"), \
         patch("nginx_doctor.cli.NginxDoctorAnalyzer") as mock_dr, \
         patch("nginx_doctor.cli.ServerAuditor") as mock_auditor, \
         patch("nginx_doctor.analyzer.wss_auditor.WSSAuditor") as mock_wss, \
         patch("nginx_doctor.checks.run_checks") as mock_run, \
         patch("nginx_doctor.cli.ReportAction") as MockReporter:
        
        mock_resolve.return_value = MagicMock()
        mock_scan.return_value = MagicMock()
        mock_dr.return_value.diagnose.return_value = []
        mock_auditor.return_value.audit.return_value = []
        mock_wss.return_value.audit.return_value = []
        mock_run.return_value = []
        
        result = runner.invoke(diagnose, ["myserver", "--score"])
        
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
         patch("nginx_doctor.checks.run_checks") as mock_run, \
         patch("nginx_doctor.cli.ReportAction") as MockReporter:
        
        mock_resolve.return_value = MagicMock()
        mock_scan.return_value = MagicMock()
        mock_dr.return_value.diagnose.return_value = []
        mock_auditor.return_value.audit.return_value = []
        mock_wss.return_value.audit.return_value = []
        mock_run.return_value = []
        
        result = runner.invoke(diagnose, ["myserver", "--explain"])
        
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
         patch("nginx_doctor.checks.run_checks") as mock_run_checks, \
         patch("nginx_doctor.cli.ReportAction") as mock_report, \
         patch("nginx_doctor.cli.SafeFixAction") as MockFixer:
        
        mock_resolve.return_value = MagicMock()
        mock_scan.return_value = MagicMock()
        mock_dr.return_value.diagnose.return_value = []
        mock_auditor.return_value.audit.return_value = []
        mock_wss.return_value.audit.return_value = []
        mock_report.return_value.report_findings.return_value = 0
        
        from nginx_doctor.model.finding import Finding
        from nginx_doctor.model.evidence import Severity, Evidence
        mock_run_checks.return_value = [Finding(
            id="TEST-1", severity=Severity.INFO, confidence=1.0, 
            condition="test", cause="test", treatment="test", impact=["test"],
            evidence=[Evidence(source_file="test", line_number=1, excerpt="test")]
        )]
        
        MockFixer.return_value.run.return_value = []
        
        result = runner.invoke(diagnose, ["myserver", "--safe-fix", "--dry-run"], obj={}, catch_exceptions=False)
        
        assert result.exit_code == 0
        MockFixer.assert_called()
        MockFixer.return_value.run.assert_called()
