"""Report Action - Generate diagnostic reports.

CONTRACT:
- read_only: True
- requires_backup: False
- rollback_support: N/A
- prerequisites: None
"""

from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nginx_doctor.engine.decision import Recommendation
from nginx_doctor.model.evidence import Evidence, Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import ServerModel


@dataclass
class ActionContract:
    """Explicit contract for an action."""

    read_only: bool
    requires_backup: bool
    rollback_support: bool
    prerequisites: list[str]


class ReportAction:
    """Generate diagnostic reports.

    This action is completely read-only and produces
    formatted output for the terminal.
    """

    CONTRACT = ActionContract(
        read_only=True,
        requires_backup=False,
        rollback_support=False,
        prerequisites=[],
    )

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def report_findings(self, findings: list[Finding]) -> None:
        """Print all findings with evidence."""
        if not findings:
            self.console.print("   [green][bold]PASS:[/] No issues found.[/]")
            return

        # Sort findings by severity: CRITICAL (0) < WARNING (1) < INFO (2)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.WARNING: 1,
            Severity.INFO: 2,
        }
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))

        # Count by severity for the summary line
        counts = {
            Severity.CRITICAL: 0,
            Severity.WARNING: 0,
            Severity.INFO: 0
        }
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        
        sum_parts = []
        if counts[Severity.CRITICAL]:
            sum_parts.append(f"[red]{counts[Severity.CRITICAL]} critical[/]")
        if counts[Severity.WARNING]:
            sum_parts.append(f"[yellow]{counts[Severity.WARNING]} warning[/]")
        if counts[Severity.INFO]:
            sum_parts.append(f"[blue]{counts[Severity.INFO]} info[/]")

        self.console.print("\n[bold]Diagnosis Results[/]")
        self.console.print(f"   Summary: {', '.join(sum_parts)}")
        self.console.print()

        for finding in sorted_findings:
            self._print_finding(finding)

    def _print_finding(self, finding: Finding) -> None:
        """Print a single finding with evidence."""
        # Severity color
        colors = {
            "critical": "red",
            "warning": "yellow",
            "info": "blue",
        }
        color = colors.get(finding.severity.value, "white")

        # Header with ID
        header = f"[bold {color}]{finding.severity_icon}:[/] [bold][{finding.id}][/] {finding.condition}"
        if finding.derived_from:
            header += f" [dim](derived_from={finding.derived_from})[/]"
        
        self.console.print(header)

        # Details
        self.console.print(f"   [dim]Cause:[/] {finding.cause}")
        self.console.print(f"   [dim]Confidence:[/] {finding.confidence:.0%}")

        # Evidence
        self.console.print("   [dim]Evidence:[/]")
        for evidence in finding.evidence:
            self.console.print(f"      - {evidence.source_file}:{evidence.line_number}")
            if evidence.excerpt:
                self.console.print(f"         [italic]{evidence.excerpt}[/]")

        # Treatment
        if finding.treatment:
            self.console.print(f"   [dim]Treatment:[/] [green]{finding.treatment}[/]")

        # Impact
        if finding.impact:
            self.console.print("   [dim]Impact if ignored:[/]")
            for impact in finding.impact:
                self.console.print(f"      ! {impact}")

        self.console.print()

    def report_recommendations(self, recommendations: list[Recommendation]) -> None:
        """Display recommendations with ranked solutions."""
        if not recommendations:
            return

        self.console.print()
        self.console.print(Panel.fit("Recommendations", style="bold yellow"))
        self.console.print()

        for rec in recommendations:
            self.console.print(f"[bold]{rec.summary}[/]")

            for solution in rec.solutions:
                rank_colors = {
                    "best": "green",
                    "acceptable": "yellow",
                    "risky": "red",
                }
                color = rank_colors.get(solution.rank.value, "white")

                self.console.print(
                    f"   [{color}]{solution.rank.value.upper()}[/]: {solution.description}"
                )

                if solution.steps:
                    for i, step in enumerate(solution.steps, 1):
                        self.console.print(f"      {i}. {step}")

                if solution.warnings:
                    for warning in solution.warnings:
                        self.console.print(f"      [red]⚠ {warning}[/]")

            self.console.print()

    def report_server_summary(self, model: ServerModel, findings: list[Finding] | None = None) -> None:
        """Display server summary table."""
        self.console.print()
        self.console.print(Panel.fit(f"📋 Server: {model.hostname}", style="bold cyan"))

        # OS info
        if model.os:
            self.console.print(f"   OS: {model.os.full_name}")

        # Nginx info
        if model.nginx:
            self.console.print(f"   Nginx: {model.nginx.version}")
            self.console.print(f"   Server Blocks: {len(model.nginx.servers)}")

        # PHP info
        if model.php:
            self.console.print(f"   PHP: {', '.join(model.php.versions)}")
            self.console.print(f"   FPM Sockets: {len(model.php.sockets)}")

        # Count health issues (WARNING/CRITICAL)
        health_issues = 0
        if findings:
            health_issues = sum(1 for f in findings if f.severity in (Severity.WARNING, Severity.CRITICAL))
        
        # Count discovery gaps (Low confidence or non-web type)
        from nginx_doctor.model.server import ProjectType
        discovery_gaps = 0
        if model.projects:
            discovery_gaps = sum(1 for p in model.projects if p.confidence < 0.7 or p.type == ProjectType.UNKNOWN)

        if health_issues:
            self.console.print(f"   [yellow]! Projects with warnings/critical issues: {health_issues}[/]")
        if discovery_gaps:
            self.console.print(f"   [blue]i Projects with low-confidence/unknown: {discovery_gaps}[/]")

        if model.projects:
            table = Table(show_header=True)
            table.add_column("Project")
            table.add_column("Type")
            table.add_column("Confidence")
            table.add_column("PHP Socket")

            for p in model.projects:
                # Disambiguate project names by showing more of the path if it's nested (e.g., ftl/app)
                path_parts = p.path.strip("/").split("/")
                if len(path_parts) >= 2 and path_parts[0] == "var" and path_parts[1] == "www":
                    display_name = "/".join(path_parts[2:])
                elif len(path_parts) >= 2:
                    display_name = "/".join(path_parts[-2:])
                else:
                    display_name = path_parts[-1] if path_parts else p.path

                # Highlight low confidence
                conf_style = "yellow" if p.confidence < 0.7 else "green"
                # Shorten socket path for display
                socket_display = p.php_socket.split("/")[-1] if p.php_socket else "[dim]—[/]"

                table.add_row(
                    display_name,
                    p.type.value,
                    f"[{conf_style}]{p.confidence:.0%}[/]",
                    socket_display,
                )

            self.console.print(table)

    def _find_php_socket_for_project(self, model: ServerModel, project_path: str) -> str | None:
        """Find the PHP socket used by a project via nginx fastcgi_pass."""
        if not model.nginx:
            return None
        
        for server in model.nginx.servers:
            # Check if this server's root matches the project
            if server.root and project_path in server.root:
                for location in server.locations:
                    if location.fastcgi_pass and "php" in location.fastcgi_pass.lower():
                        return location.fastcgi_pass.replace("unix:", "")
        return None

    def export_server_model(self, model: ServerModel, format: str) -> None:
        """Export server model to JSON or YAML."""
        import dataclasses
        import json
        
        # Convert dataclass to dict
        data = dataclasses.asdict(model)
        
        if format == "json":
            self.console.print(json.dumps(data, indent=2, default=str))
        elif format == "yaml":
            try:
                import yaml
                self.console.print(yaml.dump(data, sort_keys=False))
            except ImportError:
                self.console.print("[red]Error: PyYAML is required for YAML export[/]")

    def export_findings(self, findings: list[Finding], format: str) -> None:
        """Export findings to JSON or YAML."""
        import dataclasses
        import json
        
        data = [dataclasses.asdict(f) for f in findings]
        
        if format == "json":
            self.console.print(json.dumps(data, indent=2, default=str))
        elif format == "yaml":
            try:
                import yaml
                self.console.print(yaml.dump(data, sort_keys=False))
            except ImportError:
                self.console.print("[red]Error: PyYAML is required for YAML export[/]")
