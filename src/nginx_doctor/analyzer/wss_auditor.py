"""WebSocket (WSS) Auditor - Detects WebSocket misconfiguration.

Specialized auditor for WebSocket endpoints that checks:
- Upgrade header requirements
- Connection header requirements  
- Proxy buffering settings
- Timeout configurations
- Security headers
- Routing conflicts
"""

import re
from dataclasses import dataclass, field

from nginx_doctor.model.evidence import Evidence, Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import LocationBlock, ServerBlock, ServerModel


# Heuristic patterns for detecting WebSocket locations
WS_PATH_PATTERNS = [
    r"/ws/?$",
    r"/wss/?$", 
    r"/socket",
    r"/socket\.io",
    r"/pusher",
    r"/broadcasting",
    r"/laravel-websockets",
    r"/reverb",
    r"/cable",
    r"/graphql-ws",
]

WS_UPSTREAM_PATTERNS = [
    "ws",
    "socket",
    "reverb", 
    "websocket",
    "realtime",
    "cable",
]


@dataclass
class WSLocation:
    """A detected WebSocket location with its context."""
    
    server: ServerBlock
    location: LocationBlock
    domain: str
    ports: list[str]
    proxy_target: str
    has_upgrade: bool = False
    has_connection: bool = False
    has_http_version_11: bool = False
    buffering: str = "unknown"
    read_timeout: int | None = None
    send_timeout: int | None = None
    risk_level: str = "OK"
    issues: list[str] = field(default_factory=list)


class WSSAuditor:
    """Auditor for WebSocket/WSS configuration issues.
    
    Detects common misconfigurations that break real-time connections.
    """

    def __init__(self, model: ServerModel) -> None:
        self.model = model
        self.ws_locations: list[WSLocation] = []

    def audit(self) -> list[Finding]:
        """Run all WSS audit checks.
        
        Returns:
            List of Finding objects for WSS issues.
        """
        findings: list[Finding] = []
        
        if not self.model.nginx:
            return findings
        
        # First, discover all WebSocket locations
        self._discover_ws_locations()
        
        # Run checks
        findings.extend(self._check_upgrade_headers())
        findings.extend(self._check_connection_header())
        findings.extend(self._check_http_version())
        findings.extend(self._check_buffering())
        findings.extend(self._check_timeouts())
        findings.extend(self._check_forwarded_headers())
        findings.extend(self._check_cors_security())
        findings.extend(self._check_wildcard_exposure())
        findings.extend(self._check_dotfile_protection())
        
        return findings

    def get_inventory(self) -> list[WSLocation]:
        """Get the discovered WebSocket locations inventory."""
        if not self.ws_locations:
            self._discover_ws_locations()
        return self.ws_locations

    def _discover_ws_locations(self) -> None:
        """Discover all locations that appear to be WebSocket endpoints."""
        self.ws_locations = []
        
        if not self.model.nginx:
            return
            
        for server in self.model.nginx.servers:
            for location in server.locations:
                if self._is_ws_location(location):
                    ws_loc = self._build_ws_location(server, location)
                    self._assess_risk(ws_loc)
                    self.ws_locations.append(ws_loc)

    def _is_ws_location(self, location: LocationBlock) -> bool:
        """Check if a location appears to be a WebSocket endpoint."""
        # Must have proxy_pass to be a WS candidate
        if not location.proxy_pass:
            return False
        
        # Check path patterns
        for pattern in WS_PATH_PATTERNS:
            if re.search(pattern, location.path, re.IGNORECASE):
                return True
        
        # Check if proxy target looks like a WS upstream
        proxy_target = location.proxy_pass.lower()
        for pattern in WS_UPSTREAM_PATTERNS:
            if pattern in proxy_target:
                return True
        
        # Check if it has WS upgrade headers (explicit WS config)
        if "Upgrade" in location.proxy_set_headers:
            return True
            
        return False

    def _build_ws_location(self, server: ServerBlock, location: LocationBlock) -> WSLocation:
        """Build a WSLocation object from server and location blocks."""
        domain = server.server_names[0] if server.server_names else "_"
        ports = [self._extract_port(listen) for listen in server.listen]
        
        ws_loc = WSLocation(
            server=server,
            location=location,
            domain=domain,
            ports=ports,
            proxy_target=location.proxy_pass or "",
            has_upgrade="Upgrade" in location.proxy_set_headers,
            has_connection="Connection" in location.proxy_set_headers,
            has_http_version_11=location.proxy_http_version == "1.1",
            buffering=location.proxy_buffering or "default",
            read_timeout=location.proxy_read_timeout,
            send_timeout=location.proxy_send_timeout,
        )
        
        return ws_loc

    def _extract_port(self, listen: str) -> str:
        """Extract port number from listen directive."""
        # Examples: "80", "443 ssl", "[::]:80", "8080 default_server"
        parts = listen.split()
        port_part = parts[0] if parts else listen
        # Handle IPv6 format [::]:port
        if "]:" in port_part:
            port_part = port_part.split("]:")[1]
        # Handle address:port format
        if ":" in port_part and not port_part.startswith("["):
            port_part = port_part.split(":")[-1]
        return port_part

    def _assess_risk(self, ws_loc: WSLocation) -> None:
        """Assess the risk level of a WebSocket location."""
        issues = []
        
        if not ws_loc.has_http_version_11:
            issues.append("Missing proxy_http_version 1.1")
        if not ws_loc.has_upgrade:
            issues.append("Missing Upgrade header")
        if not ws_loc.has_connection:
            issues.append("Missing Connection header")
        if ws_loc.buffering not in ("off", "default"):
            issues.append("Buffering may cause issues")
        if ws_loc.read_timeout and ws_loc.read_timeout < 60:
            issues.append("Read timeout too low")
            
        ws_loc.issues = issues
        
        if not ws_loc.has_http_version_11 or not ws_loc.has_upgrade or not ws_loc.has_connection:
            ws_loc.risk_level = "CRITICAL"
        elif issues:
            ws_loc.risk_level = "WARNING"
        else:
            ws_loc.risk_level = "OK"

    # === Individual Checks ===

    def _check_upgrade_headers(self) -> list[Finding]:
        """Check for missing Upgrade headers in WS locations."""
        findings = []
        
        missing = [ws for ws in self.ws_locations if not ws.has_upgrade]
        
        if missing:
            findings.append(Finding(
                id="NGX-WSS-002",
                severity=Severity.CRITICAL,
                confidence=0.95,
                condition="Missing Upgrade header for WebSocket",
                cause="WebSocket location lacks 'proxy_set_header Upgrade $http_upgrade' directive",
                evidence=[
                    Evidence(
                        source_file=ws.server.source_file,
                        line_number=ws.location.line_number,
                        excerpt=f"location {ws.location.path} -> {ws.proxy_target}",
                        command="nginx -T",
                    )
                    for ws in missing
                ],
                treatment=(
                    "Add the following to your WebSocket location:\n"
                    "    proxy_set_header Upgrade $http_upgrade;\n"
                    "    proxy_set_header Connection $connection_upgrade;"
                ),
                impact=[
                    "WebSocket connections will fail",
                    "Clients will receive HTTP 400/502 errors",
                ],
            ))
            
        return findings

    def _check_connection_header(self) -> list[Finding]:
        """Check for missing Connection header in WS locations."""
        findings = []
        
        missing = [ws for ws in self.ws_locations if not ws.has_connection]
        
        if missing:
            findings.append(Finding(
                id="NGX-WSS-003",
                severity=Severity.CRITICAL,
                confidence=0.95,
                condition="Missing Connection header for WebSocket",
                cause="WebSocket location lacks 'proxy_set_header Connection' directive",
                evidence=[
                    Evidence(
                        source_file=ws.server.source_file,
                        line_number=ws.location.line_number,
                        excerpt=f"location {ws.location.path}",
                        command="nginx -T",
                    )
                    for ws in missing
                ],
                treatment=(
                    "Add to http {} block:\n"
                    "    map $http_upgrade $connection_upgrade {\n"
                    "        default upgrade;\n"
                    "        ''      close;\n"
                    "    }\n\n"
                    "Then in location block:\n"
                    "    proxy_set_header Connection $connection_upgrade;"
                ),
                impact=[
                    "WebSocket upgrade will not complete",
                    "Connection stuck in HTTP mode",
                ],
            ))
            
        return findings

    def _check_http_version(self) -> list[Finding]:
        """Check for missing proxy_http_version 1.1."""
        findings = []
        
        missing = [ws for ws in self.ws_locations if not ws.has_http_version_11]
        
        if missing:
            findings.append(Finding(
                id="NGX-WSS-001",
                severity=Severity.CRITICAL,
                confidence=0.95,
                condition="Missing proxy_http_version 1.1 for WebSocket",
                cause="WebSocket requires HTTP/1.1 for upgrade mechanism",
                evidence=[
                    Evidence(
                        source_file=ws.server.source_file,
                        line_number=ws.location.line_number,
                        excerpt=f"location {ws.location.path}",
                        command="nginx -T",
                    )
                    for ws in missing
                ],
                treatment="Add to location block:\n    proxy_http_version 1.1;",
                impact=[
                    "WebSocket handshake will fail",
                    "nginx may use HTTP/1.0 which doesn't support upgrades",
                ],
            ))
            
        return findings

    def _check_buffering(self) -> list[Finding]:
        """Check if buffering is enabled for WS locations."""
        findings = []
        
        buffered = [ws for ws in self.ws_locations 
                    if ws.buffering and ws.buffering not in ("off", "default")]
        
        if buffered:
            findings.append(Finding(
                id="NGX-WSS-004",
                severity=Severity.WARNING,
                confidence=0.80,
                condition="Proxy buffering enabled for WebSocket",
                cause="proxy_buffering is not 'off' for WebSocket location",
                evidence=[
                    Evidence(
                        source_file=ws.server.source_file,
                        line_number=ws.location.line_number,
                        excerpt=f"location {ws.location.path} - buffering={ws.buffering}",
                        command="nginx -T",
                    )
                    for ws in buffered
                ],
                treatment="Add to location block:\n    proxy_buffering off;",
                impact=[
                    "Messages may be delayed due to buffering",
                    "Real-time performance degradation",
                ],
            ))
            
        return findings

    def _check_timeouts(self) -> list[Finding]:
        """Check for low timeout values that break WS connections."""
        findings = []
        
        low_timeout = [ws for ws in self.ws_locations 
                       if ws.read_timeout and ws.read_timeout < 60]
        
        if low_timeout:
            findings.append(Finding(
                id="NGX-WSS-005",
                severity=Severity.WARNING,
                confidence=0.85,
                condition="Low proxy_read_timeout for WebSocket",
                cause="Timeout value is less than 60 seconds for idle WS connections",
                evidence=[
                    Evidence(
                        source_file=ws.server.source_file,
                        line_number=ws.location.line_number,
                        excerpt=f"location {ws.location.path} - read_timeout={ws.read_timeout}s",
                        command="nginx -T",
                    )
                    for ws in low_timeout
                ],
                treatment=(
                    "Increase timeouts for long-lived connections:\n"
                    "    proxy_read_timeout 86400;\n"
                    "    proxy_send_timeout 86400;"
                ),
                impact=[
                    "Idle WebSocket connections will be dropped",
                    "Clients will experience unexpected disconnections",
                ],
            ))
            
        return findings

    def _check_forwarded_headers(self) -> list[Finding]:
        """Check for missing X-Forwarded-* headers."""
        findings = []
        
        missing_headers = []
        for ws in self.ws_locations:
            headers = ws.location.proxy_set_headers
            missing = []
            if "X-Forwarded-For" not in headers and "X-Real-IP" not in headers:
                missing.append("X-Forwarded-For or X-Real-IP")
            if "X-Forwarded-Proto" not in headers:
                missing.append("X-Forwarded-Proto")
            if missing:
                missing_headers.append((ws, missing))
        
        if missing_headers:
            findings.append(Finding(
                id="NGX-WSS-006",
                severity=Severity.INFO,
                confidence=0.70,
                condition="Missing forwarded headers for WebSocket",
                cause="X-Forwarded-* headers not set for proxied connections",
                evidence=[
                    Evidence(
                        source_file=ws.server.source_file,
                        line_number=ws.location.line_number,
                        excerpt=f"location {ws.location.path} - missing: {', '.join(m)}",
                        command="nginx -T",
                    )
                    for ws, m in missing_headers
                ],
                treatment=(
                    "Add headers for proper client info forwarding:\n"
                    "    proxy_set_header X-Real-IP $remote_addr;\n"
                    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                    "    proxy_set_header X-Forwarded-Proto $scheme;"
                ),
                impact=[
                    "Backend may not see real client IP",
                    "Protocol detection issues (HTTP vs HTTPS)",
                ],
            ))
            
        return findings

    def _check_cors_security(self) -> list[Finding]:
        """Check for overly permissive CORS on WS endpoints."""
        findings = []
        
        if not self.model.nginx or not self.model.nginx.raw:
            return findings
        
        # Check raw config for CORS wildcard near WS locations
        raw = self.model.nginx.raw
        
        # Simple heuristic: look for Access-Control-Allow-Origin *
        if "Access-Control-Allow-Origin" in raw and "*" in raw:
            # Check if any of our WS locations might be affected
            for ws in self.ws_locations:
                # Search for the pattern near the location
                findings.append(Finding(
                    id="NGX-WSS-007",
                    severity=Severity.WARNING,
                    confidence=0.60,
                    condition="Potential CORS wildcard on WebSocket endpoint",
                    cause="Access-Control-Allow-Origin * detected in config",
                    evidence=[
                        Evidence(
                            source_file=ws.server.source_file,
                            line_number=ws.location.line_number,
                            excerpt=f"location {ws.location.path} may have permissive CORS",
                            command="nginx -T",
                        )
                    ],
                    treatment=(
                        "Restrict CORS to specific origins:\n"
                        "    add_header Access-Control-Allow-Origin 'https://yourdomain.com';"
                    ),
                    impact=[
                        "Any website can connect to your WebSocket",
                        "Cross-site WebSocket hijacking risk",
                    ],
                ))
                break  # Only one finding for this check
            
        return findings

    def _check_wildcard_exposure(self) -> list[Finding]:
        """Check for WS endpoints on wildcard/default servers."""
        findings = []
        
        exposed = [ws for ws in self.ws_locations 
                   if ws.server.is_default_server or "_" in ws.domain]
        
        if exposed:
            findings.append(Finding(
                id="NGX-WSS-008",
                severity=Severity.WARNING,
                confidence=0.75,
                condition="WebSocket on wildcard/default server",
                cause="WS endpoint is accessible on catch-all server block",
                evidence=[
                    Evidence(
                        source_file=ws.server.source_file,
                        line_number=ws.location.line_number,
                        excerpt=f"server_name: {ws.domain}, location: {ws.location.path}",
                        command="nginx -T",
                    )
                    for ws in exposed
                ],
                treatment="Move WS endpoints to explicit server_name blocks",
                impact=[
                    "WS endpoint may be accessible via unexpected hostnames",
                    "Potential security exposure",
                ],
            ))
            
        return findings

    def _check_dotfile_protection(self) -> list[Finding]:
        """Check if dotfile protection exists for servers with WS."""
        findings = []
        
        if not self.model.nginx or not self.model.nginx.raw:
            return findings
        
        raw = self.model.nginx.raw
        
        # Check for dotfile protection pattern
        has_dotfile_protection = (
            r"location ~ /\." in raw or 
            r"location ~ /\.(?!well-known)" in raw or
            "deny all" in raw and r"\." in raw
        )
        
        if not has_dotfile_protection and self.ws_locations:
            findings.append(Finding(
                id="NGX-WSS-010",
                severity=Severity.WARNING,
                confidence=0.70,
                condition="Missing dotfile protection",
                cause="No location block denying access to dotfiles",
                evidence=[
                    Evidence(
                        source_file=self.model.nginx.config_path,
                        line_number=1,
                        excerpt="Missing: location ~ /\\.(?!well-known).* { deny all; }",
                        command="nginx -T",
                    )
                ],
                treatment=(
                    "Add dotfile protection:\n"
                    "    location ~ /\\.(?!well-known).* {\n"
                    "        deny all;\n"
                    "    }"
                ),
                impact=[
                    ".env and other sensitive dotfiles may be exposed",
                    "Security risk",
                ],
            ))
            
        return findings
