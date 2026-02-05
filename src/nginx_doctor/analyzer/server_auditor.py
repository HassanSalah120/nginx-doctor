"""Server Auditor - Security and sanity checks.

Advisory findings for security concerns and best practices.
These are non-breaking but potentially dangerous issues.
"""

from nginx_doctor.model.evidence import Evidence, Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import ProjectType, ServerModel


class ServerAuditor:
    """Server auditor for security and sanity checks.

    Checks for:
    - World-writable directories
    - Exposed .env files
    - Permission issues
    - PHP version mismatches
    - SSL certificate issues
    """

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run all audit checks.

        Returns:
            List of advisory Finding objects.
        """
        findings: list[Finding] = []

        findings.extend(self._check_env_exposure())
        findings.extend(self._check_ssl_configuration())
        findings.extend(self._check_php_version_consistency())

        return findings

    def _check_env_exposure(self) -> list[Finding]:
        """Check if .env files might be exposed."""
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        for project in self.model.projects:
            if not project.env_path:
                continue

            # Check if there's a location block blocking .env access
            has_env_protection = False

            for server in self.model.nginx.servers:
                for location in server.locations:
                    # Look for patterns like `location ~ /\.` or specific .env blocks
                    if ".env" in location.path or "/\\." in location.path:
                        has_env_protection = True
                        break

            if not has_env_protection:
                findings.append(
                    Finding(
                        severity=Severity.WARNING,
                        confidence=0.70,
                        condition=".env file may be exposed",
                        cause=f"No nginx location block found to protect .env at {project.env_path}",
                        evidence=[
                            Evidence(
                                source_file=project.env_path,
                                line_number=1,
                                excerpt=".env file exists",
                                command="filesystem scan",
                            )
                        ],
                        treatment=(
                            "Add to nginx config:\n"
                            "location ~ /\\.(?!well-known).* {\n"
                            "    deny all;\n"
                            "}"
                        ),
                        impact=[
                            "Database credentials could be exposed",
                            "API keys could be leaked",
                            "Security vulnerability",
                        ],
                    )
                )

        return findings

    def _check_ssl_configuration(self) -> list[Finding]:
        """Check SSL configuration for issues."""
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        for server in self.model.nginx.servers:
            # Check for servers with port 443 but no SSL
            if any("443" in listen and "ssl" not in listen.lower() for listen in server.listen):
                findings.append(
                    Finding(
                        severity=Severity.WARNING,
                        confidence=0.85,
                        condition="Port 443 without SSL directive",
                        cause="Server listens on 443 but 'ssl' not in listen directive",
                        evidence=[
                            Evidence(
                                source_file=server.source_file,
                                line_number=server.line_number,
                                excerpt=f"listen {', '.join(server.listen)}",
                                command="nginx -T",
                            )
                        ],
                        treatment="Add 'ssl' to listen directive: listen 443 ssl;",
                        impact=[
                            "SSL may not be properly enabled",
                            "HTTPS might not work correctly",
                        ],
                    )
                )

            # Check for SSL without certificate
            if server.ssl_enabled and not server.ssl_certificate:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        condition="SSL enabled without certificate",
                        cause="Server has SSL enabled but no ssl_certificate directive",
                        evidence=[
                            Evidence(
                                source_file=server.source_file,
                                line_number=server.line_number,
                                excerpt="ssl_certificate missing",
                                command="nginx -T",
                            )
                        ],
                        treatment="Add ssl_certificate and ssl_certificate_key directives",
                        impact=[
                            "nginx will fail to start or reload",
                            "HTTPS will not work",
                        ],
                    )
                )

        return findings

    def _check_php_version_consistency(self) -> list[Finding]:
        """Check if server blocks use consistent PHP versions."""
        findings: list[Finding] = []

        if not self.model.php or not self.model.nginx:
            return findings

        # Collect active sockets from all server blocks
        active_sockets: dict[str, list[str]] = {}  # socket -> [server_names]
        
        for server in self.model.nginx.servers:
            # Check all locations for fastcgi_pass
            for loc in server.locations:
                if loc.fastcgi_pass and loc.fastcgi_pass.startswith("unix:"):
                    socket = loc.fastcgi_pass.replace("unix:", "").strip()
                    if socket not in active_sockets:
                        active_sockets[socket] = []
                    
                    name = server.server_names[0] if server.server_names else "default"
                    if name not in active_sockets[socket]:
                        active_sockets[socket].append(name)

        if len(active_sockets) > 1:
            # Multiple versions are actually in use across different sites
            evidence_list = []
            for socket, sites in active_sockets.items():
                evidence_list.append(
                    Evidence(
                        source_file=socket,
                        line_number=1,
                        excerpt=f"Used by: {', '.join(sites[:3])}{'...' if len(sites) > 3 else ''}",
                        command="nginx -T",
                    )
                )

            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    confidence=0.90,
                    condition="Mixed PHP versions in use",
                    cause=f"Found {len(active_sockets)} different PHP-FPM sockets being used across site configurations",
                    evidence=evidence_list,
                    treatment="Consolidate projects to a single PHP version unless specifically required otherwise",
                    impact=[
                        "Higher memory usage (multiple FPM pools)",
                        "Maintenance overhead",
                        "Potential developer confusion",
                    ],
                )
            )
        elif len(self.model.php.versions) > 1:
            # Multiple installed but one or zero in use in nginx
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    confidence=0.80,
                    condition="Multiple PHP versions installed",
                    cause=f"Server has {', '.join(self.model.php.versions)} installed, but Nginx configuration is consistent",
                    evidence=[
                        Evidence(
                            source_file="/usr/bin/php",
                            line_number=1,
                            excerpt=f"Default CLI: PHP {self.model.php.default_version}",
                            command="php -v",
                        )
                    ],
                    treatment="Consider removing unused PHP versions to reduce attack surface and disk usage",
                    impact=[
                        "Unnecessary disk space usage",
                        "Security maintenance overhead",
                    ],
                )
            )

        return findings

