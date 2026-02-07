"""Plain Text Reporter Implementation."""

from rich.console import Console
from rich.text import Text

from nginx_doctor.actions.reporters.base import BaseReporter
from nginx_doctor.model.evidence import Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import ServerModel


class PlainReporter(BaseReporter):
    """Generates clean, text-only output."""

    def report_findings(self, findings: list[Finding]) -> int:
        """Report diagnosis findings to the console."""
        sorted_findings = sorted(
            findings, 
            key=lambda x: (
                0 if x.severity == Severity.CRITICAL else 
                1 if x.severity == Severity.WARNING else 2
            )
        )

        warning_count = sum(1 for f in findings if f.severity == Severity.WARNING)
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        info_count = len(findings) - warning_count - critical_count

        self.console.print()
        
        if self.show_score:
            self._print_score_summary(findings)
            self.console.print()

        self.console.print("DIAGNOSIS RESULTS", style="bold")
        self.console.print(f"Summary: {critical_count} critical, {warning_count} warning, {info_count} info")
        self.console.print()

        for finding in sorted_findings:
            self._print_finding(finding)

        return 1 if warning_count > 0 or critical_count > 0 else 0

    def _print_score_summary(self, findings: list[Finding]) -> None:
        """Print the 0-100 score card."""
        from nginx_doctor.engine.scoring import ScoringEngine
        scorer = ScoringEngine()
        score = scorer.calculate(findings)
        
        self.console.print(f"Server Health Score: {score.total}/100")
        self.console.print(f"Security: {score.security.current_points}/{score.security.max_points}")
        self.console.print(f"Performance: {score.performance.current_points}/{score.performance.max_points}")
        self.console.print(f"Architecture: {score.architecture.current_points}/{score.architecture.max_points}")
        self.console.print(f"Laravel/App: {score.app.current_points}/{score.app.max_points}")

    def _print_finding(self, finding: Finding) -> None:
        """Print a single finding."""
        severity_label = f"[{finding.severity.value.upper()}]"
        title = f"{finding.id}: {finding.condition}"
        if finding.derived_from:
            title += f" (derived_from={finding.derived_from})"
            
        self.console.print(f"{severity_label}: {title}")
        self.console.print(f"   Cause: {finding.cause}")
        self.console.print(f"   Confidence: {finding.confidence:.0%}")
        
        if finding.evidence:
            self.console.print("   Evidence:")
            for ev in finding.evidence:
                line = f"      - file={ev.source_file} line={ev.line_number}"
                if ev.excerpt:
                    clean_excerpt = ev.excerpt.replace('\n', ' ').strip()
                    line += f" excerpt=\"{clean_excerpt}\""
                self.console.print(line)

        if finding.treatment:
            self.console.print("   Treatment:")
            treatment_lines = str(finding.treatment).split('\n')
            for line in treatment_lines:
                self.console.print(f"      {line}")
        
        if finding.impact:
            self.console.print("   Impact if ignored:")
            for impact in finding.impact:
                self.console.print(f"      ! {impact}")

        if self.show_explain:
            from nginx_doctor.engine.knowledge_base import get_explanation
            expl = get_explanation(finding.id)
            if expl:
                self.console.print("   Explanation:")
                self.console.print(f"      Why: {expl.why}")
                self.console.print(f"      Risk: {expl.risk}")
                self.console.print(f"      When to ignore: {expl.ignore}")
        self.console.print()

    def report_server_summary(self, model: ServerModel, findings: list[Finding] | None = None) -> None:
        """Display server summary."""
        self.console.print(f"SERVER: {model.hostname}")

        if model.os:
            self.console.print(f"OS: {model.os.full_name}")
        if model.nginx:
            source_info = f"{model.nginx.mode}"
            if model.nginx.container_id:
                source_info += f" ({model.nginx.container_id[:12]})"
            self.console.print(f"Nginx: {model.nginx.version} (Source: {source_info})")
        if model.php:
            self.console.print(f"PHP: {', '.join(model.php.versions)}")

        if model.projects:
            self.console.print("\nPROJECTS:")
            for p in model.projects:
                self.console.print(f"- {p.path} ({p.type.value}) [Conf: {p.confidence:.0%}]")

    def report_wss_inventory(self, inventory: list) -> None:
        """Report WebSocket inventory."""
        if not inventory:
            return
            
        self.console.print("\nWEBSOCKET (WSS) INVENTORY")
        for ws in inventory:
            status = "OK" if ws.risk_level == "OK" else ws.risk_level
            self.console.print(f"[{status}] {ws.domain}:{','.join(ws.ports)} {ws.location.path}")
            self.console.print(f"   Target: {ws.proxy_target}")
            self.console.print(f"   Upgrade: {'Yes' if ws.has_upgrade else 'No'}, Connection: {'Yes' if ws.has_connection else 'No'}")
            if ws.issues:
                self.console.print(f"   Issues: {', '.join(ws.issues)}")
            self.console.print()
