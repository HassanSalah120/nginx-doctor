"""Shared scan + diagnosis pipeline.

Extracts the core logic from cli.py so both CLI and web can reuse it.
Public API:
    run_full_scan(ssh) -> ServerModel
    run_full_diagnosis(model, ssh, ...) -> DiagnosisResult
"""

import contextlib
import datetime
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from nginx_doctor import __version__
from nginx_doctor.analyzer.app_detector import AppDetector
from nginx_doctor.analyzer.correlation_engine import CorrelationEngine
from nginx_doctor.analyzer.nginx_doctor import NginxDoctorAnalyzer
from nginx_doctor.analyzer.server_auditor import ServerAuditor
from nginx_doctor.connector.ssh import SSHConnector
from nginx_doctor.engine.deduplication import deduplicate_findings
from nginx_doctor.engine.scoring import ScoringEngine
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import ServerModel
from nginx_doctor.parser.nginx_conf import NginxConfigParser
from nginx_doctor.scanner.certbot import CertbotScanner
from nginx_doctor.scanner.docker import DockerScanner
from nginx_doctor.scanner.filesystem import FilesystemScanner
from nginx_doctor.scanner.firewall import FirewallScanner
from nginx_doctor.scanner.mysql import MySQLScanner
from nginx_doctor.scanner.network_surface import NetworkSurfaceScanner
from nginx_doctor.scanner.nginx import NginxScanner
from nginx_doctor.scanner.nodejs import NodeScanner
from nginx_doctor.scanner.php import PHPScanner
from nginx_doctor.scanner.redis import RedisScanner
from nginx_doctor.scanner.security_baseline import SecurityBaselineScanner
from nginx_doctor.scanner.systemd import SystemdScanner
from nginx_doctor.scanner.telemetry import TelemetryScanner
from nginx_doctor.scanner.tls_status import TLSStatusScanner
from nginx_doctor.scanner.upstream_probe import UpstreamProbeScanner
from nginx_doctor.scanner.vulnerability import VulnerabilityScanner
from nginx_doctor.scanner.workers import WorkerScanner


@dataclass
class DiagnosisResult:
    """Result from run_full_diagnosis()."""

    findings: list[Finding]
    score: int
    topology_snapshot: dict[str, Any]
    trend: Any = None
    ws_inventory: list[Any] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    waiver_source: str | None = None


def run_full_scan(
    ssh: SSHConnector,
    *,
    log_fn: Callable[[str], None] | None = None,
) -> ServerModel:
    """Run all scanners and build the ServerModel.

    Extracted from cli.py:_scan_server(). This is the read-only scanning phase.

    Args:
        ssh: Active SSH connection.
        log_fn: Optional callback for progress logging (used by web job runner).

    Returns:
        Fully populated ServerModel.
    """
    def _log(msg: str) -> None:
        if log_fn:
            log_fn(msg)

    _log("Starting filesystem scan...")
    os_scanner = FilesystemScanner(ssh)
    from nginx_doctor.scanner.nginx_collector import NginxCollector
    collector = NginxCollector(ssh)
    nginx_data = collector.collect()

    nginx_scanner = NginxScanner(ssh)
    php_scanner = PHPScanner(ssh)

    os_info = os_scanner.get_os_info()
    from nginx_doctor.model.server import PHPInfo
    php_data = php_scanner.scan()
    php_info = PHPInfo(
        versions=php_data.versions,
        default_version=php_data.default_version,
        sockets=php_data.fpm_sockets,
        fpm_configs=php_data.pool_configs,
    )

    _log("Scanning secondary services...")
    docker_scanner = DockerScanner(ssh)
    mysql_scanner = MySQLScanner(ssh)
    node_scanner = NodeScanner(ssh)
    network_scanner = NetworkSurfaceScanner(ssh)
    firewall_scanner = FirewallScanner(ssh)
    telemetry_scanner = TelemetryScanner(ssh)
    baseline_scanner = SecurityBaselineScanner(ssh)
    vulnerability_scanner = VulnerabilityScanner(ssh)

    docker_data = docker_scanner.scan()
    mysql_data = mysql_scanner.scan()
    node_data = node_scanner.scan()
    network_data = network_scanner.scan()
    firewall_details = firewall_scanner.scan_details()
    firewall_state = firewall_details.get("state", "unknown")
    telemetry_data = telemetry_scanner.scan()
    baseline_data = baseline_scanner.scan()
    vulnerability_data = vulnerability_scanner.scan()

    from nginx_doctor.model.server import ServicesModel
    services = ServicesModel(
        docker=docker_data.status,
        docker_containers=docker_data.containers,
        mysql=mysql_data.status,
        mysql_config_detected=mysql_data.config_detected,
        mysql_bind_addresses=mysql_data.bind_addresses,
        node=node_data.status,
        node_processes=node_data.processes,
        firewall=firewall_state,
        firewall_ufw_enabled=firewall_details.get("ufw_enabled"),
        firewall_ufw_default_incoming=firewall_details.get("ufw_default_incoming"),
        firewall_rules=firewall_details.get("rules", []),
    )

    _log("Scanning runtime intelligence...")
    systemd_scanner = SystemdScanner(ssh)
    redis_scanner = RedisScanner(ssh)
    worker_scanner = WorkerScanner(ssh)

    systemd_data = systemd_scanner.scan()
    redis_data = redis_scanner.scan()
    worker_data = worker_scanner.scan()

    from nginx_doctor.model.server import RuntimeModel
    runtime = RuntimeModel(
        systemd=systemd_data.status,
        systemd_services=systemd_data.services,
        redis=redis_data.status,
        redis_instances=redis_data.instances,
        workers=worker_data.status,
        worker_processes=worker_data.processes,
        scheduler_detected=worker_data.scheduler_detected,
        scheduler_type=worker_data.scheduler_type,
    )

    _log("Parsing nginx configuration...")
    parser = NginxConfigParser()
    nginx_info = parser.parse(nginx_data.config_dump, version=nginx_data.version)
    nginx_info.mode = nginx_data.mode
    nginx_info.container_id = nginx_data.container_id
    nginx_info.path_mapping = nginx_data.path_mapping
    certbot_scanner = CertbotScanner(ssh)
    tls_scanner = TLSStatusScanner(ssh)
    probe_scanner = UpstreamProbeScanner(ssh)
    certbot_data = certbot_scanner.scan(nginx_info)
    tls_data = tls_scanner.scan(nginx_info)
    probe_enabled = os.getenv("NGINX_DOCTOR_ACTIVE_PROBES", "1").strip().lower() not in {
        "0", "false", "no", "off"
    }
    upstream_probes = probe_scanner.scan(nginx_info, enabled=probe_enabled)

    # Discovery (Server-Block Centric)
    valid_roots, skipped_roots = nginx_scanner.get_all_roots(nginx_info)
    nginx_info.skipped_paths = skipped_roots

    _log("Detecting applications...")
    detector = AppDetector()
    candidate_roots: dict[str, dict] = {}

    for server in nginx_info.servers:
        roots = []
        if server.root:
            roots.append(nginx_scanner._normalize_project_path(server.root))
        else:
            for loc in server.locations:
                if loc.root:
                    roots.append(nginx_scanner._normalize_project_path(loc.root))
                if loc.alias:
                    roots.append(nginx_scanner._normalize_project_path(loc.alias))

        for root in roots:
            if nginx_scanner._is_dynamic_path(root):
                continue
            actual_host_path = nginx_info.translate_path(root)
            if actual_host_path not in candidate_roots:
                candidate_roots[actual_host_path] = {"domains": [], "source": "nginx"}
            names = server.server_names if server.server_names else ["default"]
            for name in names:
                if name not in candidate_roots[actual_host_path]["domains"]:
                    candidate_roots[actual_host_path]["domains"].append(name)

    # Discovery via Docker Bind Mounts
    for container in services.docker_containers:
        for mount in container.mounts:
            if mount.get("type") == "bind":
                host_path = mount.get("source")
                if host_path:
                    normalized_path = nginx_scanner._normalize_project_path(host_path)
                    if normalized_path not in candidate_roots:
                        candidate_roots[normalized_path] = {
                            "domains": [f"Docker: {container.name}"],
                            "source": "docker",
                        }

    # Discovery via Node Processes
    for proc in services.node_processes:
        if proc.cwd:
            host_cwd = proc.cwd
            source_label = f"Node PID: {proc.pid}"
            if proc.container_id:
                container = next(
                    (c for c in services.docker_containers
                     if c.id and c.id.startswith(proc.container_id)),
                    None,
                )
                if container:
                    host_cwd = container.translate_path(proc.cwd)
                    source_label = f"Node in Docker: {container.name}"
            normalized_cwd = nginx_scanner._normalize_project_path(host_cwd)
            if normalized_cwd not in candidate_roots:
                candidate_roots[normalized_cwd] = {
                    "domains": [source_label],
                    "source": "node",
                }

    # Scan all unique candidates
    unique_paths = sorted(candidate_roots.keys(), key=len)
    projects: list = []

    for site_path in unique_paths:
        if not ssh.dir_exists(site_path):
            continue

        scan_data = os_scanner.scan_directory(site_path)
        basename = site_path.split("/")[-1].lower()
        asset_folders = {"assets", "images", "img", "css", "js", "storage", "build", "fonts"}

        composer_content = ssh.read_file(f"{site_path}/composer.json")
        composer_json = None
        if composer_content:
            try:
                composer_json = json.loads(composer_content)
            except Exception:
                pass

        package_content = ssh.read_file(f"{site_path}/package.json")
        package_json = None
        if package_content:
            try:
                package_json = json.loads(package_content)
            except Exception:
                pass

        detection = detector.detect(
            scan_data,
            composer_json=composer_json,
            package_json=package_json,
            docker_containers=services.docker_containers,
        )

        if basename in asset_folders and detection.confidence < 0.5:
            continue

        project_info = detector.to_project_info(scan_data, detection)
        project_info.discovery_source = candidate_roots[site_path]["source"]

        # Socket Mapping
        from nginx_doctor.actions.report import ReportAction
        from rich.console import Console as _RichConsole
        _dummy_console = _RichConsole(quiet=True)
        reporter_dummy = ReportAction(_dummy_console)
        project_info.php_socket = reporter_dummy._find_php_socket_for_project(
            ServerModel(hostname="", nginx=nginx_info),
            project_info.path,
        )

        projects.append(project_info)

    # Get local git hash
    commit_hash = "unknown"
    try:
        commit_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            cwd=Path(__file__).parent.parent,
        ).decode().strip()
    except Exception:
        pass

    model = ServerModel(
        hostname=ssh.config.host,
        os=os_info,
        nginx=nginx_info,
        nginx_status=nginx_data.status,
        php=php_info,
        services=services,
        projects=projects,
        telemetry=telemetry_data,
        security_baseline=baseline_data,
        vulnerability=vulnerability_data,
        certbot=certbot_data,
        tls=tls_data,
        network_surface=network_data,
        upstream_probes=upstream_probes,
        scan_timestamp=datetime.datetime.now().isoformat(),
        doctor_version=__version__,
        commit_hash=commit_hash,
        runtime=runtime,
    )

    # Correlation
    correlator = CorrelationEngine(model)
    correlator.correlate_all()

    _log("Scan complete.")
    return model


def run_full_diagnosis(
    model: ServerModel,
    ssh: SSHConnector,
    *,
    enable_history: bool = True,
    waiver_file: Path | None = None,
    minimal: bool = False,
    laravel: bool = True,
    ports: bool = True,
    security: bool = True,
    phpfpm: bool = True,
    performance: bool = True,
    log_fn: Callable[[str], None] | None = None,
) -> DiagnosisResult:
    """Run all analyzers/checks and produce scored findings.

    Extracted from cli.py:diagnose(). This is the analysis + scoring phase.

    Args:
        model: ServerModel from run_full_scan().
        ssh: Active SSH connection(needed by modular checks).
        enable_history: Track scan trends across runs.
        waiver_file: Optional YAML waiver file path.
        minimal: If True, only run baseline analyzers.
        laravel/ports/security/phpfpm/performance: Enable/disable specific checks.
        log_fn: Optional callback for progress logging.

    Returns:
        DiagnosisResult with findings, score, topology, trend, etc.
    """
    def _log(msg: str) -> None:
        if log_fn:
            log_fn(msg)

    _log("Running analyzers...")
    dr_analyzer = NginxDoctorAnalyzer(model)

    from nginx_doctor.analyzer.wss_auditor import WSSAuditor
    from nginx_doctor.analyzer.docker_auditor import DockerAuditor
    from nginx_doctor.analyzer.node_auditor import NodeAuditor
    from nginx_doctor.analyzer.systemd_auditor import SystemdAuditor
    from nginx_doctor.analyzer.redis_auditor import RedisAuditor
    from nginx_doctor.analyzer.worker_auditor import WorkerAuditor
    from nginx_doctor.analyzer.mysql_auditor import MySQLAuditor
    from nginx_doctor.analyzer.firewall_auditor import FirewallAuditor
    from nginx_doctor.analyzer.telemetry_auditor import TelemetryAuditor
    from nginx_doctor.analyzer.security_baseline_auditor import SecurityBaselineAuditor
    from nginx_doctor.analyzer.vulnerability_auditor import VulnerabilityAuditor
    from nginx_doctor.analyzer.network_surface_auditor import NetworkSurfaceAuditor
    from nginx_doctor.analyzer.path_conflict_auditor import PathConflictAuditor
    from nginx_doctor.analyzer.runtime_drift_auditor import RuntimeDriftAuditor
    from nginx_doctor.analyzer.certbot_auditor import CertbotAuditor

    wss_auditor = WSSAuditor(model)

    def _safe_audit(label: str, fn: Callable) -> list:
        try:
            return fn()
        except Exception:
            return []

    legacy_findings = dr_analyzer.diagnose(
        additional_findings=(
            ServerAuditor(model).audit()
            + _safe_audit("WSS", wss_auditor.audit)
            + _safe_audit("Docker", DockerAuditor(model).audit)
            + _safe_audit("Node", NodeAuditor(model).audit)
            + _safe_audit("Systemd", SystemdAuditor(model).audit)
            + _safe_audit("Redis", RedisAuditor(model).audit)
            + _safe_audit("Worker", WorkerAuditor(model).audit)
            + _safe_audit("MySQL", MySQLAuditor(model).audit)
            + _safe_audit("Firewall", FirewallAuditor(model).audit)
            + _safe_audit("Telemetry", TelemetryAuditor(model).audit)
            + _safe_audit("SecurityBaseline", SecurityBaselineAuditor(model).audit)
            + _safe_audit("Vulnerability", VulnerabilityAuditor(model).audit)
            + _safe_audit("NetworkSurface", NetworkSurfaceAuditor(model).audit)
            + _safe_audit("PathConflict", PathConflictAuditor(model).audit)
            + _safe_audit("RuntimeDrift", RuntimeDriftAuditor(model).audit)
            + _safe_audit("Certbot", CertbotAuditor(model).audit)
        )
    )

    _log("Running modular checks...")
    from nginx_doctor.checks import CheckContext, run_checks
    import nginx_doctor.checks.laravel.laravel_auditor
    import nginx_doctor.checks.ports.port_auditor
    import nginx_doctor.checks.security.security_auditor
    import nginx_doctor.checks.phpfpm.phpfpm_auditor
    import nginx_doctor.checks.performance.performance_auditor

    default_enabled = not minimal

    check_ctx = CheckContext(
        model=model,
        ssh=ssh,
        laravel_enabled=default_enabled or laravel,
        ports_enabled=default_enabled or ports,
        security_enabled=default_enabled or security,
        phpfpm_enabled=default_enabled or phpfpm,
        performance_enabled=default_enabled or performance,
    )

    new_findings = run_checks(check_ctx)
    findings = deduplicate_findings(legacy_findings + new_findings)

    _log("Applying waivers...")
    from nginx_doctor.engine.waivers import apply_waivers, default_waiver_path, load_waiver_rules
    actual_waiver_file = waiver_file or default_waiver_path()
    waiver_rules = load_waiver_rules(actual_waiver_file)
    findings, suppressed_findings = apply_waivers(findings, waiver_rules)
    waiver_source = str(actual_waiver_file) if waiver_rules else None

    ws_inventory = wss_auditor.get_inventory()
    from nginx_doctor.engine.topology import build_topology_snapshot
    topology_snapshot = build_topology_snapshot(model, ws_inventory)

    _log("Computing scores...")
    score_total = ScoringEngine().calculate(findings).total

    # Compute trend against previous scan
    trend = None
    if enable_history:
        from nginx_doctor.engine.history import ScanHistoryStore
        tracker = ScanHistoryStore()
        current_ts = model.scan_timestamp or datetime.datetime.now().isoformat()
        history_host = model.hostname if isinstance(getattr(model, "hostname", None), str) else "unknown"
        trend = tracker.compute_trend(
            history_host,
            findings,
            score_total,
            current_ts,
            current_topology=topology_snapshot,
        )
        tracker.append_scan(
            history_host,
            findings,
            score_total,
            current_ts,
            topology=topology_snapshot,
        )

    _log("Diagnosis complete.")
    return DiagnosisResult(
        findings=findings,
        score=score_total,
        topology_snapshot=topology_snapshot,
        trend=trend,
        ws_inventory=ws_inventory,
        suppressed_findings=suppressed_findings,
        waiver_source=waiver_source,
    )
