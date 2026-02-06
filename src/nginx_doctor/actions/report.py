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

    def __init__(self, console: Console | None = None, format_mode: str = "rich", no_wrap: bool = False) -> None:
        self.console = console or Console()
        self.format_mode = format_mode
        self.no_wrap = no_wrap

    def report_findings(self, findings: list[Finding]) -> int:
        """Report diagnosis findings to the console."""
            
        # JSON Mode
        if self.format_mode == "json":
            import json
            from dataclasses import asdict
            # Convert findings to dicts, manually handling Enum serialization if needed
            data = [asdict(f) for f in findings]
            # Simple enum serialization fix
            for item in data:
                item['severity'] = item['severity'].value if hasattr(item['severity'], 'value') else str(item['severity'])
                item['evidence'] = [asdict(e) for e in findings[data.index(item)].evidence]
            self.console.print(json.dumps(data, indent=2))
            return 1 if any(f.severity in (Severity.CRITICAL, Severity.WARNING) for f in findings) else 0

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

        self._print()
        self._print("Diagnosis Results", style="bold underline")
        self._print(f"   Summary: {critical_count} critical, {warning_count} warning, {info_count} info")
        self._print()

        for finding in sorted_findings:
            self._print_finding(finding)

        return 1 if warning_count > 0 or critical_count > 0 else 0

    def _print(self, text: str = "", style: str | None = None) -> None:
        """Print helper that respects plain mode."""
        if self.format_mode == "plain":
            # Strip simple markup for plain mode if needed, or rely on Console(force_terminal=False)
            # But we want to avoid specific rich artifacts like panels
            if style and "bold" in style:
                pass # Could add uppercase or similar
            # Remove markup tags for plain text
            from rich.text import Text
            plain_text = Text.from_markup(text).plain
            self.console.print(plain_text)
        else:
            self.console.print(text, style=style)

    def _print_finding(self, finding: Finding) -> None:
        """Print a single finding with format-aware logic."""
        if self.format_mode == "plain":
            severity_label = f"[{finding.severity.value.upper()}]"
            title = f"{finding.id}: {finding.condition}"
            if finding.derived_from:
                title += f" (derived_from={finding.derived_from})"
                
            self.console.print(f"\n{severity_label}: {title}")
            self.console.print(f"   Cause: {finding.cause}")
            self.console.print(f"   Confidence: {finding.confidence:.0%}")
            
            if finding.evidence:
                self.console.print("   Evidence:")
                for ev in finding.evidence:
                    # STRICT SINGLE LINE
                    line = f"      - file={ev.source_file} line={ev.line_number}"
                    if ev.excerpt:
                        # Sanitize newlines in excerpt
                        clean_excerpt = ev.excerpt.replace('\n', ' ').strip()
                        line += f" excerpt=\"{clean_excerpt}\""
                    self.console.print(line)

            if finding.treatment:
                self.console.print("   Treatment:")
                # Pre-formatted block for plain text
                treatment_lines = str(finding.treatment).split('\n')
                for line in treatment_lines:
                    self.console.print(f"      {line}")
            
            if finding.impact:
                self.console.print("   Impact if ignored:")
                for impact in finding.impact:
                    self.console.print(f"      ! {impact}")
                    
        else:
            # Rich Mode (Existing logic with enhancements)
            color = "white"
            icon = "i"
            if finding.severity == Severity.CRITICAL:
                color = "red"
                icon = "x"
            elif finding.severity == Severity.WARNING:
                color = "yellow"
                icon = "!"

            title = f"[{color}][{finding.severity.value}] {icon} [{finding.id}] {finding.condition}[/]"
            if finding.derived_from:
                title += f" [dim](derived_from={finding.derived_from})[/]"
            
            self.console.print(title)
            self.console.print(f"   [dim]Cause:[/] {finding.cause}")
            self.console.print(f"   [dim]Confidence:[/] {finding.confidence:.0%}")

            self.console.print("   [dim]Evidence:[/]")
            for evidence in finding.evidence:
                # Rich auto-wraps, but we can try to keep it cleaner
                loc = f"{evidence.source_file}:{evidence.line_number}"
                self.console.print(f"      - {loc}")
                if evidence.excerpt:
                    self.console.print(f"         [italic]{evidence.excerpt}[/]")

            if finding.treatment:
                treatment_text = str(finding.treatment)
                if "\n" in treatment_text:
                    # Panel logic for rich mode
                    from rich.panel import Panel
                    self.console.print("   [dim]Treatment:[/]")
                    is_command = "sudo " in treatment_text
                    title = "[bold white]Terminal Action[/]" if is_command else "[bold white]Configuration Change[/]"
                    border = "green" if is_command else "blue"
                    
                    self.console.print(
                        Panel(
                            f"[green]{treatment_text}[/]" if is_command else f"[blue]{treatment_text}[/]",
                            title=title,
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
            
            self.console.print()

    def report_recommendations(self, recommendations: list[Recommendation]) -> None:
        """Display recommendations with ranked solutions."""
        if not recommendations:
            return
        if self.format_mode == "json": return
        
        if self.format_mode == "plain":
            self.console.print("\nRecommendations:")
            for rec in recommendations:
                self.console.print(f"\n* {rec.summary}")
                for sol in rec.solutions:
                    self.console.print(f"  - [{sol.rank.value.upper()}] {sol.description}")
                    if sol.steps:
                        for i, step in enumerate(sol.steps, 1):
                            self.console.print(f"      {i}. {step}")
                    if sol.warnings:
                        for warning in sol.warnings:
                            self.console.print(f"      WARNING: {warning}")
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

                table.add_row(display_name, f"[{conf_style}]{p.type.value}[/]", f"[{conf_style}]{p.confidence:.0%}[/]", socket_display)

            self.console.print(table)

    def report_inventory(self, inventory: list[dict], base_path: str) -> None:
        """Report filesystem inventory discovery results."""
        if self.format_mode == "json":
            import json
            # Convert enums values
            clean_inv = []
            for item in inventory:
                new_item = item.copy()
                new_item['type'] = item['type'].value
                if item['nginx_project']:
                    # Serialize Nginx project info partially
                    new_item['nginx_project'] = {
                        'path': item['nginx_project'].path,
                        'type': item['nginx_project'].type.value,
                        'conf': item['nginx_project'].confidence
                    }
                else:
                    new_item['nginx_project'] = None
                # Serialize scan data partially (exclude complex objects)
                new_item['scan'] = {
                    'files': item['nginx_project'].scan.files if item.get('nginx_project') and hasattr(item['nginx_project'], 'scan') else [],
                    # Simplified
                }
                # Actually, simpler to just dump basics
                del new_item['scan'] 
                clean_inv.append(new_item)
            self.console.print(json.dumps(clean_inv, indent=2))
            return

        # Prepare categories
        configured = [i for i in inventory if i['status'] == "configured"]
        unreferenced = [i for i in inventory if i['status'] == "unreferenced" and i['type'].value != "unknown"]
        noise = [i for i in inventory if i['status'] == "unreferenced" and i['type'].value == "unknown"]

        if self.format_mode == "plain":
            self.console.print(f"\nFilesystem Discovery Report (Base: {base_path})")
            self.console.print(f"Total Folders Scanned: {len(inventory)}")
            self.console.print(f"Configured in Nginx: {len(configured)}")
            self.console.print(f"Unreferenced Projects: {len(unreferenced)}")
            self.console.print(f"Static/Noise: {len(noise)}")
            
            if unreferenced:
                self.console.print("\n⚠️  Unreferenced Projects (Orphaned):")
                for item in unreferenced:
                    self.console.print(f"   - {item['path']} ({item['type'].value}) [Conf: {item.get('conf', 0):.0%}]")
            
            if configured:
                 self.console.print("\n✅ Configured Projects:")
                 for item in configured:
                     self.console.print(f"   - {item['path']} (Matched Nginx root)")
            return

        # Rich Mode
        from rich.table import Table
        from rich.panel import Panel

        self.console.print()
        self.console.print(Panel(
            f"[bold]Filesystem Inventory: {base_path}[/]\n"
            f"Active: [green]{len(configured)}[/] | Unreferenced: [yellow]{len(unreferenced)}[/] | Noise: [dim]{len(noise)}[/]",
            title="🔍 Discovery Results",
            border_style="cyan"
        ))
        
        if unreferenced:
            table = Table(title="⚠️  Unreferenced Projects (On Disk but Not in Nginx)", show_header=True)
            table.add_column("Path", style="yellow")
            table.add_column("Detected Type")
            table.add_column("Confidence")
            
            for item in unreferenced:
                table.add_row(
                    item['path'],
                    item['type'].value,
                    f"{item.get('conf',0):.0%}"
                )
            self.console.print(table)
            
        if configured:
            self.console.print(f"\n[green]✅ Found {len(configured)} projects correctly configured in Nginx.[/]")
            
        if noise:
            self.console.print(f"[dim]Note: {len(noise)} folders skipped as static/unknown (e.g. {noise[0]['path']}...)[/]")

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

    def report_wss_inventory(self, ws_locations: list) -> None:
        """Report WebSocket locations inventory.
        
        Args:
            ws_locations: List of WSLocation objects from WSSAuditor.get_inventory()
        """
        if not ws_locations:
            return
            
        if self.format_mode == "json":
            import json
            data = [
                {
                    "domain": ws.domain,
                    "ports": ws.ports,
                    "path": ws.location.path,
                    "proxy_target": ws.proxy_target,
                    "has_upgrade": ws.has_upgrade,
                    "has_connection": ws.has_connection,
                    "has_http_version_11": ws.has_http_version_11,
                    "buffering": ws.buffering,
                    "read_timeout": ws.read_timeout,
                    "risk_level": ws.risk_level,
                    "issues": ws.issues,
                }
                for ws in ws_locations
            ]
            self.console.print(json.dumps(data, indent=2))
            return
            
        if self.format_mode == "plain":
            self.console.print("\n🔌 WebSocket (WSS) Inventory")
            self.console.print("-" * 60)
            for ws in ws_locations:
                status = "✓" if ws.risk_level == "OK" else ("⚠" if ws.risk_level == "WARNING" else "✗")
                self.console.print(f"{status} {ws.domain}:{','.join(ws.ports)} {ws.location.path}")
                self.console.print(f"   Target: {ws.proxy_target}")
                self.console.print(f"   Upgrade: {'Yes' if ws.has_upgrade else 'No'}, Connection: {'Yes' if ws.has_connection else 'No'}, HTTP/1.1: {'Yes' if ws.has_http_version_11 else 'No'}")
                if ws.issues:
                    self.console.print(f"   Issues: {', '.join(ws.issues)}")
                self.console.print()
            return
            
        # Rich mode
        from rich.panel import Panel
        from rich.table import Table
        
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
        
        for ws in ws_locations:
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
