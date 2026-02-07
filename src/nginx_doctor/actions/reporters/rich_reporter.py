"""Rich Reporter Implementation."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nginx_doctor.actions.reporters.base import BaseReporter
from nginx_doctor.model.evidence import Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import ServerModel


class RichReporter(BaseReporter):
    """Generates high-fidelity terminal output using Rich."""

    def report_findings(self, findings: list[Finding]) -> int:
        """Report diagnosis findings to the console."""
        # Sort by severity
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

        self.console.print("Diagnosis Results", style="bold underline")
        self.console.print(f"   Summary: {critical_count} critical, {warning_count} warning, {info_count} info")
        self.console.print()

        for finding in sorted_findings:
            self._print_finding(finding)

        return 1 if warning_count > 0 or critical_count > 0 else 0

    def _print_score_summary(self, findings: list[Finding]) -> None:
        """Print the 0-100 score card."""
        from nginx_doctor.engine.scoring import ScoringEngine
        scorer = ScoringEngine()
        score = scorer.calculate(findings)
        
        total_color = "red"
        if score.total >= 80: total_color = "green"
        elif score.total >= 60: total_color = "yellow"
        
        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_column(justify="right")
        
        def row(name, cur, max_p):
            c = "green" if cur == max_p else ("yellow" if cur > max_p/2 else "red")
            grid.add_row(name, f"[{c}]{cur}[/][dim]/{max_p}[/]")
            
        row("Security", score.security.current_points, score.security.max_points)
        row("Performance", score.performance.current_points, score.performance.max_points)
        row("Architecture", score.architecture.current_points, score.architecture.max_points)
        row("Laravel/App", score.app.current_points, score.app.max_points)
        
        self.console.print(Panel(
            grid,
            title=f"[{total_color}]Server Health Score: {score.total}/100[/]",
            border_style=total_color
        ))

    def _print_finding(self, finding: Finding) -> None:
        """Print a single finding."""
        color = "white"
        icon = "i"
        if finding.severity == Severity.CRITICAL:
            color = "red"
            icon = "x"
        elif finding.severity == Severity.WARNING:
            color = "yellow"
            icon = "!"
        elif finding.severity == Severity.INFO:
            color = "blue"
            icon = "i"

        title = f"[{color}][{finding.severity.value}] {icon} [{finding.id}] {finding.condition}[/]"
        if finding.derived_from:
            title += f" [dim](derived_from={finding.derived_from})[/]"
        
        self.console.print(title)
        self.console.print(f"   [dim]Cause:[/] {finding.cause}")
        self.console.print(f"   [dim]Confidence:[/] {finding.confidence:.0%}")

        self.console.print("   [dim]Evidence:[/]")
        for evidence in finding.evidence:
            loc = f"{evidence.source_file}:{evidence.line_number}"
            self.console.print(f"      - {loc}")
            if evidence.excerpt:
                self.console.print(f"         [italic]{evidence.excerpt}[/]")

        if finding.treatment:
            treatment_text = str(finding.treatment)
            if "\n" in treatment_text:
                is_command = "sudo " in treatment_text
                p_title = "[bold white]Terminal Action[/]" if is_command else "[bold white]Configuration Change[/]"
                border = "green" if is_command else "blue"
                
                self.console.print(
                    Panel(
                        f"[green]{treatment_text}[/]" if is_command else f"[blue]{treatment_text}[/]",
                        title=p_title,
                        title_align="left",
                        border_style=border,
                        padding=(1, 2)
                    )
                )
            else:
                self.console.print(f"   [dim]Treatment:[/] [green]{finding.treatment}[/]")

        if finding.impact:
            self.console.print("   [dim]Impact if ignored:[/]")
            for impact in finding.impact:
                self.console.print(f"      ! {impact}")
        
        if self.show_explain:
            from nginx_doctor.engine.knowledge_base import get_explanation
            expl = get_explanation(finding.id)
            if expl:
                self.console.print("   [bold cyan]Explanation:[/]")
                self.console.print(f"      [cyan]Why:[/cyan] {expl.why}")
                self.console.print(f"      [cyan]Risk:[/cyan] {expl.risk}")
                self.console.print(f"      [cyan]Ignore if:[/cyan] {expl.ignore}")
        
        self.console.print()

    def report_server_summary(self, model: ServerModel, findings: list[Finding] | None = None) -> None:
        """Display server summary."""
        self.console.print()
        self.console.print(Panel.fit(f"📋 Server: {model.hostname}", style="bold cyan"))

        if model.os:
            self.console.print(f"   OS: {model.os.full_name}")
        if model.nginx:
            self.console.print(f"   Nginx: {model.nginx.version}")
            self.console.print(f"   Server Blocks: {len(model.nginx.servers)}")
        if model.php:
            self.console.print(f"   PHP: {', '.join(model.php.versions)}")
            self.console.print(f"   FPM Sockets: {len(model.php.sockets)}")

        health_issues = 0
        if findings:
            health_issues = sum(1 for f in findings if f.severity in (Severity.WARNING, Severity.CRITICAL))
        
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
                path_parts = p.path.strip("/").split("/")
                if len(path_parts) >= 2 and path_parts[0] == "var" and path_parts[1] == "www":
                    display_name = "/".join(path_parts[2:])
                elif len(path_parts) >= 2:
                    display_name = "/".join(path_parts[-2:])
                else:
                    display_name = path_parts[-1] if path_parts else p.path

                conf_style = "yellow" if p.confidence < 0.7 else "green"
                socket_display = p.php_socket.split("/")[-1] if p.php_socket else "[dim]—[/]"

                table.add_row(display_name, f"[{conf_style}]{p.type.value}[/]", f"[{conf_style}]{p.confidence:.0%}[/]", socket_display)

            self.console.print(table)

    def report_wss_inventory(self, inventory: list) -> None:
        """Report WebSocket inventory."""
        if not inventory:
            return
            
        self.console.print()
        self.console.print(Panel.fit("🔌 WebSocket (WSS) Inventory", style="bold magenta"))
        self.console.print()
        
        table = Table(show_header=True, header_style="bold white", expand=True)
        table.add_column("Domain")
        table.add_column("Ports")
        table.add_column("WS Path")
        table.add_column("Proxy Target")
        table.add_column("Upgrade", justify="center")
        table.add_column("Risk", justify="center")
        
        for ws in inventory:
            risk_style = {
                "OK": "[green]OK[/]",
                "WARNING": "[yellow]WARN[/]",
                "CRITICAL": "[red]CRIT[/]",
            }.get(ws.risk_level, ws.risk_level)
            
            upgrade_icon = "[green]✓[/]" if ws.has_upgrade and ws.has_connection and ws.has_http_version_11 else "[red]✗[/]"
            
            table.add_row(
                ws.domain,
                ", ".join(ws.ports),
                ws.location.path,
                ws.proxy_target[:30] + "..." if len(ws.proxy_target) > 30 else ws.proxy_target,
                upgrade_icon,
                risk_style,
            )
        
        self.console.print(table)
