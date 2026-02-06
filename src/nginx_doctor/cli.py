"""
Click-based CLI for nginx-doctor.

IMPORTANT: This module only ORCHESTRATES. It never reasons or makes decisions.
- Loads server profiles
- Invokes engine
- Passes flags
- Formats output
"""

import contextlib
import click
from rich.console import Console
from rich.panel import Panel

from nginx_doctor import __version__
from nginx_doctor.actions.apply import ApplyAction
from nginx_doctor.actions.generate import GenerateAction
from nginx_doctor.actions.report import ReportAction
from nginx_doctor.actions.html_report import HTMLReportAction
from nginx_doctor.analyzer.app_detector import AppDetector
from nginx_doctor.analyzer.nginx_doctor import NginxDoctorAnalyzer
from nginx_doctor.analyzer.server_auditor import ServerAuditor
from nginx_doctor.config import ConfigManager
from nginx_doctor.connector.ssh import SSHConfig, SSHConnector
from nginx_doctor.engine.decision import DecisionEngine
from nginx_doctor.model.server import ServerModel
from nginx_doctor.parser.nginx_conf import NginxConfigParser
from nginx_doctor.scanner.filesystem import FilesystemScanner
from nginx_doctor.scanner.nginx import NginxScanner
from nginx_doctor.scanner.php import PHPScanner

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="nginx-doctor")
@click.option("--config", "-c", type=click.Path(), help="Path to config directory")
@click.pass_context
def main(ctx: click.Context, config: str | None) -> None:
    """🩺 nginx-doctor: SSH-based Server Intelligence System.

    Diagnose Nginx + PHP problems, audit server health, and generate configs.
    """
    from pathlib import Path
    ctx.ensure_object(dict)
    config_dir = Path(config) if config else None
    ctx.obj["config_mgr"] = ConfigManager(config_dir)


def _resolve_config(ctx: click.Context, server: str) -> SSHConfig:
    """Resolve server string to SSHConfig (profile name or IP)."""
    config_mgr = ctx.obj["config_mgr"]
    cfg = config_mgr.get_profile(server)
    if cfg:
        return cfg
    
    # Otherwise treat as hostname/IP with default root user
    return SSHConfig(host=server, user="root")


def _scan_server(ctx: click.Context, ssh: SSHConnector) -> ServerModel:
    """Internal helper to run all scanners and build model."""
    with console.status("[bold blue]🔍 Scanning server...[/]"):
        os_scanner = FilesystemScanner(ssh)
        nginx_scanner = NginxScanner(ssh)
        php_scanner = PHPScanner(ssh)
        
        os_info = os_scanner.get_os_info()
        from nginx_doctor.model.server import PHPInfo
        nginx_data = nginx_scanner.scan()
        php_data = php_scanner.scan()
        php_info = PHPInfo(
            versions=php_data.versions,
            default_version=php_data.default_version,
            sockets=php_data.fpm_sockets,
            fpm_configs=php_data.pool_configs,
        )
        
        # Parse nginx config
        parser = NginxConfigParser()
        nginx_info = parser.parse(nginx_data.full_config, version=nginx_data.version)
        
        # PHASE 2: Discovery (Server-Block Centric)
        valid_roots, skipped_roots = nginx_scanner.get_all_roots(nginx_info)
        nginx_info.skipped_paths = skipped_roots
        
        # App detection
        detector = AppDetector()
        projects = []
        
        # 1. Collect roots grouped by server block to ensure domain association
        server_projects: dict[str, list[str]] = {} # root -> [server_names]
        
        for server in nginx_info.servers:
            # Prefer server root
            roots = []
            if server.root:
                roots.append(nginx_scanner._normalize_project_path(server.root))
            else:
                # Fallback to location roots if no server root exists
                for loc in server.locations:
                    if loc.root:
                        roots.append(nginx_scanner._normalize_project_path(loc.root))
                    if loc.alias:
                        roots.append(nginx_scanner._normalize_project_path(loc.alias))
            
            for root in roots:
                if nginx_scanner._is_dynamic_path(root):
                    continue
                if root not in server_projects:
                    server_projects[root] = []
                names = server.server_names if server.server_names else ["default"]
                for name in names:
                    if name not in server_projects[root]:
                        server_projects[root].append(name)

        # 2. Filter and scan unique roots
        sorted_roots = sorted(server_projects.keys(), key=len)
        final_roots = []
        for root in sorted_roots:
            # Skip if this root is a subdirectory of an already processed root
            if any(root.startswith(r + "/") for r in final_roots):
                continue
            final_roots.append(root)

        for site_path in final_roots:
            if not ssh.dir_exists(site_path):
                continue
                
            scan_data = os_scanner.scan_directory(site_path)
            
            # STRICTOR FILTER: If it's a directory like 'assets', 'images', 'storage' 
            # and contains no index files or composer.json, skip it.
            basename = site_path.split("/")[-1].lower()
            asset_folders = {"assets", "images", "img", "css", "js", "storage", "build", "fonts"}
            
            # Try to read composer.json
            composer_content = ssh.read_file(f"{site_path}/composer.json")
            import json
            composer_json = None
            if composer_content:
                try:
                    composer_json = json.loads(composer_content)
                except:
                    pass
            
            detection = detector.detect(scan_data, composer_json)
            
            # If it's a known asset folder and detection is weak, skip it
            if basename in asset_folders and detection.confidence < 0.5:
                continue
            
            project_info = detector.to_project_info(scan_data, detection)
            
            # PHASE 3: Socket Mapping
            from nginx_doctor.actions.report import ReportAction
            reporter_dummy = ReportAction(console)
            project_info.php_socket = reporter_dummy._find_php_socket_for_project(
                ServerModel(hostname="", nginx=nginx_info), 
                project_info.path
            )
            
            projects.append(project_info)
            
        return ServerModel(
            hostname=ssh.config.host,
            os=os_info,
            nginx=nginx_info,
            php=php_info,
            projects=projects
        )


@main.command()
@click.argument("server")
@click.pass_context
def check(ctx: click.Context, server: str) -> None:
    """CI/CD friendly one-shot command.
    
    Runs scan, diagnose, and recommend. 
    Exits with code 1 if warnings or critical findings exist.
    """
    import sys
    from nginx_doctor.model.evidence import Severity
    
    cfg = _resolve_config(ctx, server)
    try:
        with SSHConnector(cfg) as ssh:
            model = _scan_server(ctx, ssh)
            
            # Run analyzers
            dr_analyzer = NginxDoctorAnalyzer(model)
            auditor = ServerAuditor(model)
            findings = dr_analyzer.diagnose(additional_findings=auditor.audit())
            
            # Report everything
            reporter = ReportAction(console)
            reporter.report_server_summary(model, findings)
            reporter.report_findings(findings)
            
            engine = DecisionEngine(model, findings)
            recs = engine.recommend()
            reporter.report_recommendations(recs)
            
            # Check for severity (Critical = 2, Warning = 1, Info/None = 0)
            exit_code = 0
            for f in findings:
                if f.severity == Severity.CRITICAL:
                    exit_code = 2
                    break
                if f.severity == Severity.WARNING:
                    exit_code = max(exit_code, 1)
            
            sys.exit(exit_code)
                
    except SystemExit as e:
        sys.exit(e.code)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)


@main.command()
@click.argument("server")
@click.option("--json", "output_format", flag_value="json", help="Output as JSON")
@click.option("--yaml", "output_format", flag_value="yaml", help="Output as YAML")
@click.pass_context
def scan(ctx: click.Context, server: str, output_format: str | None) -> None:
    """Scan a server and build the internal model.

    This is read-only and makes no changes to the server.
    """
    cfg = _resolve_config(ctx, server)
    try:
        with SSHConnector(cfg) as ssh:
            model = _scan_server(ctx, ssh)
            reporter = ReportAction(console)
            
            if output_format:
                reporter.export_server_model(model, output_format)
            else:
                reporter.report_server_summary(model)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")


@main.command()
@click.argument("server")
@click.option("--format", "fmt", type=click.Choice(["rich", "plain", "json", "html"]), default=None, help="Output format")
@click.option("--output", "-o", default="report.html", help="Output file for HTML report")
@click.pass_context
def diagnose(ctx: click.Context, server: str, fmt: str | None, output: str) -> None:
    """Run full diagnosis on a server.

    Identifies misconfigurations with evidence-based findings.
    """
    import sys
    cfg = _resolve_config(ctx, server)
    
    # Auto-detect format if not specified
    if fmt is None:
        fmt = "plain" if not sys.stdout.isatty() else "rich"

    try:
        with SSHConnector(cfg) as ssh:
            with console.status(f"🔍 Scanning server...", spinner="dots") if fmt == "rich" else contextlib.nullcontext():
                model = _scan_server(ctx, ssh)
            
            # Run analyzers
            dr_analyzer = NginxDoctorAnalyzer(model)
            auditor = ServerAuditor(model)
            
            findings = dr_analyzer.diagnose(additional_findings=auditor.audit())
            
            if fmt == "html":
                html_reporter = HTMLReportAction()
                report_path = html_reporter.generate(model, findings, output_path=output)
                console.print(f"\n[bold green]Report generated:[/] {report_path}")
                sys.exit(0)

            # Report with selected format
            reporter = ReportAction(console, format_mode=fmt)
            
            # Only show summary table in rich/plain mode (not json)
            if fmt != "json":
                reporter.report_server_summary(model)
            
            exit_code = reporter.report_findings(findings)
            
            # Store in context in case user wants to pipe to recommend
            ctx.obj['findings'] = findings
            ctx.obj['model'] = model
            
            sys.exit(exit_code)
            
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        import traceback
        traceback.print_exc()


@main.command()
@click.argument("server")
@click.option("--base", default="/var/www", help="Base directory to scan (default: /var/www)")
@click.option("--format", "fmt", type=click.Choice(["rich", "plain", "json", "html"]), default=None)
@click.option("--output", "-o", default="inventory.html", help="Output file for HTML report")
@click.pass_context
def discover(ctx: click.Context, server: str, base: str, fmt: str | None, output: str) -> None:
    """Discover filesystem projects and match with Nginx.
    
    Reveals orphaned projects that exist on disk but are not served by Nginx.
    """
    import sys
    cfg = _resolve_config(ctx, server)
    
    if fmt is None:
        fmt = "plain" if not sys.stdout.isatty() else "rich"
        
    # Import needed classes locally to avoid circular dependencies if any
    from nginx_doctor.scanner.filesystem import FilesystemScanner
    from nginx_doctor.analyzer.app_detector import AppDetector

    try:
        with SSHConnector(cfg) as ssh:
            # 1. Get Truth (Nginx)
            with console.status(f"🔍 Scanning active Nginx config...", spinner="dots") if fmt == "rich" else contextlib.nullcontext():
                model = _scan_server(ctx, ssh)
            
            # 2. Get Inventory (Filesystem)
            fs_scanner = FilesystemScanner(ssh)
            detector = AppDetector()
            
            with console.status(f"📂 Crawling {base}...", spinner="dots") if fmt == "rich" else contextlib.nullcontext():
                candidate_paths = fs_scanner.crawl_projects(base)
                
            filesystem_projects = []
            
            # Analyze each candidate
            with console.status(f"🕵️ Analyzing {len(candidate_paths)} folders...", spinner="dots") if fmt == "rich" else contextlib.nullcontext():
                for path in candidate_paths:
                    d_scan = fs_scanner.scan_directory(path)
                    
                    # Check for composer usage to improve detection
                    composer_data = None
                    if d_scan.has_composer_json:
                        content = fs_scanner.get_file_content(f"{path}/composer.json")
                        if content:
                            try:
                                import json
                                composer_data = json.loads(content)
                            except: pass
                            
                    detection = detector.detect(d_scan, composer_data)
                    
                    # Create ProjectInfo (lightweight version)
                    filesystem_projects.append({
                        "path": path,
                        "type": detection.project_type,
                        "conf": detection.confidence,
                        "scan": d_scan
                    })

            # 3. Correlate
            # Map Nginx roots to these fs paths
            # Logic: If Nginx root is /var/www/foo/public, it matches /var/www/foo
            
            inventory = []
            
            for fs_proj in filesystem_projects:
                path = fs_proj['path']
                status = "unreferenced"
                matched_nginx_project = None
                
                # Check against Nginx projects
                for nginx_proj in model.projects:
                    # Check exact or subpath logic
                    # If nginx project path (normalized) is inside fs path or equals
                    # NginxScanner normalizes roots to project base usually.
                    if nginx_proj.path == path:
                        status = "configured"
                        matched_nginx_project = nginx_proj
                        break
                    
                    # Also check if nginx root starts with this fs path (e.g. fs=/var/www/app, nginx=/var/www/app/public)
                    if nginx_proj.path.startswith(path + "/"):
                         status = "configured"
                         matched_nginx_project = nginx_proj
                         break
                
                inventory.append({
                    "path": path,
                    "type": fs_proj['type'],
                    "status": status,
                    "nginx_project": matched_nginx_project
                })
                
            # Report
            if fmt == "html":
                unreferenced = []
                static_noise = []
                
                for item in inventory:
                    if item['status'] == 'unreferenced':
                        # Classify by type
                        if item['type'] in [ProjectType.STATIC, ProjectType.UNKNOWN]:
                            static_noise.append(item['path'])
                        else:
                            unreferenced.append(item)
                
                html_reporter = HTMLReportAction()
                report_path = html_reporter.generate(
                    model, 
                    output_path=output, 
                    unreferenced=unreferenced,
                    static_noise=static_noise
                )
                console.print(f"\n[bold green]Inventory Report generated:[/] {report_path}")
                sys.exit(0)

            reporter = ReportAction(console, format_mode=fmt)
            reporter.report_inventory(inventory, base)
            
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        import traceback
        traceback.print_exc()


@main.command()
@click.argument("server")
@click.pass_context
def recommend(ctx: click.Context, server: str) -> None:
    """Get recommendations for a server.

    Provides ranked solutions (best → acceptable → risky).
    """
    cfg = _resolve_config(ctx, server)
    try:
        with SSHConnector(cfg) as ssh:
            model = _scan_server(ctx, ssh)
            
            dr_analyzer = NginxDoctorAnalyzer(model)
            auditor = ServerAuditor(model)
            findings = dr_analyzer.diagnose() + auditor.audit()
            
            engine = DecisionEngine(model, findings)
            recs = engine.recommend()
            
            reporter = ReportAction(console)
            reporter.report_recommendations(recs)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")


@main.command()
@click.argument("server")
@click.option("--project", "-p", help="Specific project to generate config for")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def generate(
    ctx: click.Context, server: str, project: str | None, output: str | None
) -> None:
    """Generate Nginx configuration for a server/project.

    This is read-only. Configs are written locally, not to the server.
    """
    cfg = _resolve_config(ctx, server)
    try:
        with SSHConnector(cfg) as ssh:
            model = _scan_server(ctx, ssh)
            
            gen = GenerateAction()
            # If no project specified, take first one
            proj = None
            if project:
                proj = next((p for p in model.projects if project in p.path), None)
            elif model.projects:
                proj = model.projects[0]
            
            if not proj:
                console.print("[yellow]No project found to generate config for.[/]")
                return

            # Default domain to hostname if not known
            domain = model.hostname
            config_text = gen.generate_laravel_config(proj, domain)
            
            if output:
                import pathlib
                gen.write_config(config_text, pathlib.Path(output))
                console.print(f"[green]✓ Config written to:[/] {output}")
            else:
                console.print(Panel(config_text, title="Generated Config", style="cyan"))
                
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")


@main.command()
@click.argument("server")
@click.option("--config", "-c", "config_file", type=click.Path(exists=True), required=True, help="Config file to apply")
@click.option("--target", "-t", required=True, help="Target path on server")
@click.option("--backup/--no-backup", default=True, help="Backup existing configs first")
@click.pass_context
def apply(
    ctx: click.Context, server: str, config_file: str, target: str, backup: bool
) -> None:
    """Apply configuration changes to a server.

    ⚠️  WARNING: This modifies the server!
    """
    cfg = _resolve_config(ctx, server)
    try:
        with SSHConnector(cfg) as ssh:
            apply_act = ApplyAction(ssh)
            import pathlib
            config_content = pathlib.Path(config_file).read_text()
            
            console.print(f"[bold yellow]⚠️  Applying config to {target}...[/]")
            if click.confirm("Are you sure you want to proceed?"):
                result = apply_act.apply_config(config_content, target, backup=backup)
                if result.success:
                    console.print("[bold green]✓ Successfully applied and reloaded nginx![/]")
                else:
                    console.print(f"[bold red]Error:[/] {result.error}")
                    if result.nginx_test_output:
                        console.print(f"[dim]Nginx test output:[/]\n{result.nginx_test_output}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")


@main.group()
def config() -> None:
    """Manage server connection profiles."""
    pass


@config.command("add")
@click.argument("name")
@click.option("--host", "-h", required=True, help="Server hostname or IP")
@click.option("--user", "-u", default="root", help="SSH username")
@click.option("--port", "-p", default=22, help="SSH port")
@click.option("--password", "-pass", help="SSH password")
@click.option("--key", "-k", type=click.Path(), help="Path to SSH private key")
@click.option("--sudo/--no-sudo", default=True, help="Use sudo for commands")
@click.pass_context
def config_add(
    ctx: click.Context, name: str, host: str, user: str, port: int, password: str | None, key: str | None, sudo: bool
) -> None:
    """Add a new server profile."""
    config_mgr = ctx.obj["config_mgr"]
    cfg = SSHConfig(host=host, user=user, port=port, password=password, key_path=key, use_sudo=sudo)
    config_mgr.add_profile(name, cfg)
    console.print(f"[bold green]✓ Added server profile:[/] {name}")


@config.command("list")
@click.pass_context
def config_list(ctx: click.Context) -> None:
    """List all server profiles."""
    config_mgr = ctx.obj["config_mgr"]
    profiles = config_mgr.list_profiles()
    if not profiles:
        console.print("[dim]No profiles configured yet.[/]")
        return
        
    for name, data in profiles.items():
        console.print(f"[bold green]{name}[/]: {data['user']}@{data['host']}:{data['port']}")


@config.command("remove")
@click.argument("name")
@click.pass_context
def config_remove(ctx: click.Context, name: str) -> None:
    """Remove a server profile."""
    config_mgr = ctx.obj["config_mgr"]
    if config_mgr.remove_profile(name):
        console.print(f"[bold green]✓ Removed profile:[/] {name}")
    else:
        console.print(f"[bold red]Error:[/] Profile {name} not found.")


if __name__ == "__main__":
    main()
