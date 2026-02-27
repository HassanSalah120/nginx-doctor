"""Server model dataclasses - Core data structures representing server state."""

from dataclasses import dataclass, field
from enum import Enum


class ProjectType(Enum):
    """Detected project/framework type."""

    LARAVEL = "laravel"
    PHP_MVC = "php_mvc"
    STATIC = "static"
    REACT_SPA = "react_spa"
    VUE_SPA = "vue_spa"
    NODE_API = "node_api"
    NODE_SSR = "node_ssr"
    REACT_STATIC_BUILD = "react_static_build"
    REACT_SOURCE = "react_source"
    NEXTJS = "nextjs"
    NUXT = "nuxt"
    DOCKERIZED_APP = "dockerized_app"
    REVERSE_PROXY = "reverse_proxy"
    REACT_FRONTEND = "react_frontend"
    WEBSOCKET_SERVICE = "websocket_service"
    UNKNOWN = "unknown"


class CapabilityLevel(Enum):
    """Capability level for a service/scanner."""

    FULL = "full"
    LIMITED = "limited"
    NONE = "none"


class ServiceState(Enum):
    """Runtime state of a service."""

    RUNNING = "running"
    STOPPED = "stopped"
    NOT_INSTALLED = "not_installed"
    UNKNOWN = "unknown"


class CapabilityReason(Enum):
    """Reason for a specific capability level."""

    PERMISSION_DENIED = "permission_denied"
    BINARY_MISSING = "binary_missing"
    SOCKET_MISSING = "socket_missing"
    DAEMON_UNREACHABLE = "daemon_unreachable"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


@dataclass
class OSInfo:
    """Operating system information."""

    name: str  # Ubuntu, Debian, CentOS, etc.
    version: str  # 22.04, 11, 9, etc.
    codename: str | None = None  # jammy, bullseye, etc.

    @property
    def full_name(self) -> str:
        """Get full OS name with version."""
        if self.codename:
            return f"{self.name} {self.version} ({self.codename})"
        return f"{self.name} {self.version}"


@dataclass
class LocationBlock:
    """Nginx location block."""

    path: str  # /api, /static, ~* \.php$
    root: str | None = None
    alias: str | None = None
    try_files: str | None = None
    autoindex: bool = False
    fastcgi_pass: str | None = None
    proxy_pass: str | None = None
    source_file: str = ""  # Which config file this came from
    line_number: int = 0  # For evidence tracking
    
    # Headers defined with add_header
    headers: dict[str, str] = field(default_factory=dict)

    
    # WebSocket / Reverse Proxy specific
    proxy_http_version: str | None = None  # "1.1" required for WS
    proxy_set_headers: dict[str, str] = field(default_factory=dict)  # Upgrade, Connection, Host, etc.
    proxy_buffering: str | None = None  # "on" or "off"
    proxy_read_timeout: int | None = None  # seconds
    proxy_send_timeout: int | None = None  # seconds
    return_directive: str | None = None
    stub_status: bool = False
    
    # Nested locations
    locations: list["LocationBlock"] = field(default_factory=list)


@dataclass
class ServerBlock:
    """Nginx server block."""

    server_names: list[str] = field(default_factory=list)
    listen: list[str] = field(default_factory=list)  # 80, 443 ssl, etc.
    root: str | None = None
    autoindex: bool = False
    index: list[str] = field(default_factory=list)
    locations: list[LocationBlock] = field(default_factory=list)
    ssl_enabled: bool = False
    ssl_certificate: str | None = None
    ssl_certificate_key: str | None = None
    source_file: str = ""  # Which config file this came from
    line_number: int = 0  # For evidence tracking
    
    # Headers defined with add_header
    headers: dict[str, str] = field(default_factory=dict)


    @property
    def is_default_server(self) -> bool:
        """Check if this is a default/catch-all server."""
        return "_" in self.server_names or "default_server" in " ".join(self.listen)


@dataclass
class UpstreamBlock:
    """Nginx upstream block for load balancing / proxying."""
    
    name: str  # upstream name (e.g., "websocket_backend")
    servers: list[str] = field(default_factory=list)  # 127.0.0.1:6001, unix:/path/to/sock
    source_file: str = ""
    line_number: int = 0


@dataclass
class NginxInfo:
    """Nginx server information."""

    version: str
    config_path: str  # /etc/nginx/nginx.conf
    servers: list[ServerBlock] = field(default_factory=list)
    upstreams: list[UpstreamBlock] = field(default_factory=list)  # All upstream {} blocks
    includes: list[str] = field(default_factory=list)  # All included config files
    skipped_includes: list[str] = field(default_factory=list)  # Included files that were skipped
    skipped_paths: list[str] = field(default_factory=list)  # Dynamic paths like $1 skipped during scan
    
    # Global/HTTP context headers
    http_headers: dict[str, str] = field(default_factory=dict)
    
    has_connection_upgrade_map: bool = False  # True if map $http_upgrade $connection_upgrade detected
    raw: str = ""  # Full nginx -T output for reference
    
    # Phase 16: Docker-Awareness
    mode: str = "HOST"  # HOST, DOCKER, NONE
    container_id: str | None = None
    path_mapping: dict[str, str] = field(default_factory=dict)  # container_path -> host_path
    virtual_files: dict[str, str] = field(default_factory=dict)  # path -> content

    def translate_path(self, container_path: str) -> str:
        """Translate a container path to a host path using bind mounts."""
        if not self.path_mapping or self.mode != "DOCKER":
            return container_path
            
        cp = container_path.rstrip("/")
        # Try exact match first
        if cp in self.path_mapping:
            return self.path_mapping[cp]
            
        # Try prefix match (longest prefix first)
        sorted_prefixes = sorted(self.path_mapping.keys(), key=len, reverse=True)
        for prefix in sorted_prefixes:
            if cp.startswith(prefix + "/"):
                return self.path_mapping[prefix] + cp[len(prefix):]
        
        return container_path


@dataclass
class PHPInfo:
    """PHP installation information."""

    versions: list[str] = field(default_factory=list)  # 8.2.10, 8.1.25
    default_version: str | None = None
    sockets: list[str] = field(default_factory=list)  # /run/php/php8.2-fpm.sock
    fpm_configs: list[str] = field(default_factory=list)  # Pool config paths


@dataclass
class ServiceStatus:
    """Status and capability information for a service."""

    capability: CapabilityLevel
    state: ServiceState = ServiceState.UNKNOWN
    reason: CapabilityReason | None = None
    version: str | None = None
    listening_ports: list[int] = field(default_factory=list)


@dataclass
class CorrelationEvidence:
    """Evidence for Nginx-to-Entity route correlation."""

    nginx_location: str  # file path:line
    proxy_target_raw: str  # http://127.0.0.1:8080
    proxy_target_normalized: str  # 127.0.0.1:8080
    matched_entity: str  # Container name or PID
    match_confidence: str  # HIGH, MED, LOW


@dataclass
class DockerPort:
    """Docker port mapping."""

    container_port: int
    host_ip: str = "0.0.0.0"
    host_port: int | None = None
    proto: str = "tcp"


@dataclass
class DockerContainer:
    """Information about a Docker container."""

    name: str
    image: str
    status: str
    id: str | None = None
    main_pid: int | None = None
    restart_count: int = 0
    ports: list[DockerPort] = field(default_factory=list)
    mounts: list[dict[str, str]] = field(default_factory=list)

    def translate_path(self, container_path: str) -> str:
        """Translate a container-internal path to a host path."""
        if not container_path:
            return container_path
            
        cp = container_path.rstrip("/")
        # Try exact match first
        for m in self.mounts:
            if m.get("type") == "bind":
                src = m.get("source")
                dst = m.get("destination", "").rstrip("/")
                if src and dst == cp:
                    return src
        
        # Try prefix match (longest destination path first)
        sorted_mounts = sorted(
            [m for m in self.mounts if m.get("type") == "bind"], 
            key=lambda x: len(x.get("destination", "")), 
            reverse=True
        )
        for m in sorted_mounts:
            src = m.get("source")
            dst = m.get("destination", "").rstrip("/")
            if src and dst and cp.startswith(dst + "/"):
                return src + cp[len(dst):]
        
        return container_path


@dataclass
class NodeProcess:
    """Information about a running Node.js process."""

    pid: int
    cmdline: str
    cwd: str
    container_id: str | None = None
    listening_ports: list[int] = field(default_factory=list)


@dataclass
class ServicesModel:
    """Model representing secondary services on the server."""

    docker: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    docker_containers: list[DockerContainer] = field(default_factory=list)
    
    mysql: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    mysql_config_detected: bool = False
    mysql_bind_addresses: list[str] = field(default_factory=list)
    
    node: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    node_processes: list[NodeProcess] = field(default_factory=list)

    firewall: str = "unknown"  # present, not_detected, unknown
    firewall_ufw_enabled: bool | None = None
    firewall_ufw_default_incoming: str | None = None  # allow, deny, unknown
    firewall_rules: list[str] = field(default_factory=list)


@dataclass
class ProjectInfo:
    """Detected project information."""

    path: str  # /var/www/chatduel
    type: ProjectType
    confidence: float  # 0.0 - 1.0
    public_path: str | None = None  # /var/www/chatduel/public
    assets_paths: list[str] = field(default_factory=list)
    framework_version: str | None = None  # Laravel 10.x
    env_path: str | None = None  # Path to .env if exists
    composer_json: dict | None = None  # Parsed composer.json
    php_socket: str | None = None  # FPM socket used by this project
    docker_container: str | None = None  # Linked container name if applicable
    discovery_source: str = "nginx"  # nginx, docker, node
    correlation: list[CorrelationEvidence] = field(default_factory=list)


@dataclass
class SystemdService:
    """Systemd service unit information."""

    name: str
    state: str  # active, inactive, failed
    substate: str  # running, exited, dead
    restart_count: int = 0  # Best-effort (NRestarts or heuristic)
    main_pid: int | None = None
    exec_start: str | None = None
    ports: list[int] = field(default_factory=list)


@dataclass
class RedisInstance:
    """Redis instance information."""

    port: int
    state: ServiceState
    config_path: str | None = None
    auth_enabled: bool | None = None  # True=Auth, False=No Auth, None=Unknown
    bind_addresses: list[str] = field(default_factory=list)
    protected_mode: bool = False


@dataclass
class WorkerProcess:
    """Background worker process information."""

    pid: int
    cmdline: str
    queue_type: str  # laravel, node, custom
    backend: str = "unknown"  # redis, db, sqs


@dataclass
class RuntimeModel:
    """Runtime topology and service state."""
    
    systemd: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    systemd_services: list[SystemdService] = field(default_factory=list)

    redis: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    redis_instances: list[RedisInstance] = field(default_factory=list)

    workers: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    worker_processes: list[WorkerProcess] = field(default_factory=list)
    scheduler_detected: bool = False
    scheduler_type: str | None = None  # cron, systemd-timer


@dataclass
class DiskUsage:
    """Disk utilization for a mountpoint."""

    mount: str
    total_gb: float
    used_gb: float
    used_percent: float
    inode_total: int | None = None
    inode_used_percent: float | None = None


@dataclass
class SecurityBaselineModel:
    """Baseline OS/security posture snapshot."""

    ssh_permit_root_login: str | None = None
    ssh_password_authentication: str | None = None
    pending_updates_total: int | None = None
    pending_security_updates: int | None = None
    reboot_required: bool = False


@dataclass
class VulnerabilityModel:
    """Package vulnerability posture from distro security metadata."""

    provider: str = "unknown"  # apt, dnf, yum, unknown
    cve_ids: list[str] = field(default_factory=list)
    advisory_ids: list[str] = field(default_factory=list)
    affected_packages: list[str] = field(default_factory=list)


@dataclass
class CertbotModel:
    """Certbot usage and certificate-renewal posture."""

    installed: bool | None = None
    service_failed: bool = False
    timer_active: bool = False
    timer_enabled: bool = False
    uses_letsencrypt_certs: bool = False
    https_detected: bool = False
    min_days_to_expiry: int | None = None
    active_cert_paths: list[str] = field(default_factory=list)
    renew_dry_run_output: str | None = None
    systemctl_status_output: str | None = None
    journal_output: str | None = None
    unit_cat_output: str | None = None
    certificates_output: str | None = None
    renewal_dir_listing: str | None = None


@dataclass
class NetworkEndpoint:
    """Live listening endpoint on the host."""

    protocol: str  # tcp or udp
    address: str
    port: int
    pid: int | None = None
    program: str | None = None
    service: str | None = None
    public_exposed: bool = False


@dataclass
class NetworkSurfaceModel:
    """Host network exposure snapshot."""

    endpoints: list[NetworkEndpoint] = field(default_factory=list)


@dataclass
class TLSCertificateStatus:
    """TLS certificate metadata extracted from active cert paths."""

    path: str
    issuer: str | None = None
    subject: str | None = None
    expires_at: str | None = None
    days_remaining: int | None = None
    sans: list[str] = field(default_factory=list)
    parse_ok: bool = False


@dataclass
class TLSStatusModel:
    """TLS certificate posture snapshot."""

    certificates: list[TLSCertificateStatus] = field(default_factory=list)


@dataclass
class UpstreamProbeResult:
    """Optional active probe result for upstream/local backend targets."""

    target: str
    protocol: str = "tcp"  # tcp/http/https
    reachable: bool = False
    latency_ms: float | None = None
    detail: str | None = None
    scope: str = "host"  # host, nginx_container, unknown
    status: str = "UNKNOWN"  # OPEN, BLOCKED, UNKNOWN
    tcp_ok: bool | None = None
    http_code: int | None = None
    ws_code: int | None = None
    ws_status: str | None = None  # 101, 426, timeout, fail, n/a
    ws_detail: str | None = None
    ws_path: str | None = None


@dataclass
class TelemetryModel:
    """Host-level telemetry snapshot."""

    cpu_cores: int | None = None
    load_1: float | None = None
    load_5: float | None = None
    load_15: float | None = None
    mem_total_mb: int | None = None
    mem_available_mb: int | None = None
    swap_total_mb: int | None = None
    swap_free_mb: int | None = None
    disks: list[DiskUsage] = field(default_factory=list)


@dataclass
class ServerModel:
    """Complete server model - the unified view of the server state.

    All analyzers operate on this model. It is built once by the scanners
    and parsers, then passed to all analysis modules.

    This separation ensures:
    - Scanners only run commands
    - Parsers only structure data
    - Analyzers only reason about the model
    """

    hostname: str
    os: OSInfo | None = None
    nginx: NginxInfo | None = None
    nginx_status: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    php: PHPInfo | None = None
    services: ServicesModel = field(default_factory=ServicesModel)
    projects: list[ProjectInfo] = field(default_factory=list)
    runtime: RuntimeModel = field(default_factory=RuntimeModel)
    telemetry: TelemetryModel = field(default_factory=TelemetryModel)
    security_baseline: SecurityBaselineModel = field(default_factory=SecurityBaselineModel)
    vulnerability: VulnerabilityModel = field(default_factory=VulnerabilityModel)
    certbot: CertbotModel = field(default_factory=CertbotModel)
    tls: TLSStatusModel = field(default_factory=TLSStatusModel)
    network_surface: NetworkSurfaceModel = field(default_factory=NetworkSurfaceModel)
    upstream_probes: list[UpstreamProbeResult] = field(default_factory=list)
    scan_timestamp: str = ""  # ISO format timestamp
    doctor_version: str = ""
    commit_hash: str = ""

    @property
    def project_count(self) -> int:
        """Get number of detected projects."""
        return len(self.projects)

    def get_project(self, name: str) -> ProjectInfo | None:
        """Find a project by name (directory name)."""
        for project in self.projects:
            if project.path.rstrip("/").split("/")[-1] == name:
                return project
        return None
