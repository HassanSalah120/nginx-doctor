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
    
    node: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    node_processes: list[NodeProcess] = field(default_factory=list)

    firewall: str = "unknown"  # present, not_detected, unknown


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
