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


@dataclass
class PHPInfo:
    """PHP installation information."""

    versions: list[str] = field(default_factory=list)  # 8.2.10, 8.1.25
    default_version: str | None = None
    sockets: list[str] = field(default_factory=list)  # /run/php/php8.2-fpm.sock
    fpm_configs: list[str] = field(default_factory=list)  # Pool config paths


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
    php: PHPInfo | None = None
    projects: list[ProjectInfo] = field(default_factory=list)
    scan_timestamp: str = ""  # ISO format timestamp

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
