"""Docker Auditor - Identifies misconfigurations in containerized environments.
"""

from nginx_doctor.model.evidence import Evidence, Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import ServerModel


class DockerAuditor:
    """Auditor for Docker-specific diagnostic checks."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run all Docker diagnostic checks."""
        findings: list[Finding] = []
        if self.model.services.docker.capability == "none":
            return findings

        findings.extend(self._check_container_restarts())
        findings.extend(self._check_direct_exposure())
        findings.extend(self._check_socket_permissions())
        return findings

    def _check_container_restarts(self) -> list[Finding]:
        """Check for containers in restart loops (DOCKER-1)."""
        findings: list[Finding] = []
        for container in self.model.services.docker_containers:
            if container.restart_count >= 5:
                severity = Severity.CRITICAL if container.restart_count >= 20 else Severity.WARNING
                findings.append(Finding(
                    severity=severity,
                    confidence=1.0,
                    condition=f"Docker container '{container.name}' is restarting frequently",
                    cause=f"Restart count is {container.restart_count}",
                    evidence=[Evidence(
                        source_file="docker",
                        line_number=1,
                        excerpt=f"Container: {container.name}, Image: {container.image}, Restarts: {container.restart_count}",
                        command="docker inspect"
                    )],
                    treatment="Check container logs using 'docker logs " + container.name + "' to identify the crash cause.",
                    impact=["Service instability", "Potential data corruption", "Resource exhaustion"],
                    correlation=self._get_correlations(container.name)
                ))
        return findings

    def _check_direct_exposure(self) -> list[Finding]:
        """Check for published ports not proxied by Nginx (DOCKER-2 / SHADOW-1)."""
        findings: list[Finding] = []
        
        # 1. Map all host ports covered by Nginx via correlation
        covered_host_ports = set()
        for project in self.model.projects:
            for ev in project.correlation:
                if "Docker" in ev.matched_entity:
                    # Extract port from normalized target e.g. 127.0.0.1:8080
                    if ":" in ev.proxy_target_normalized:
                        try:
                            covered_host_ports.add(int(ev.proxy_target_normalized.split(":")[1]))
                        except ValueError:
                            continue

        # 2. Check each container's published ports
        for container in self.model.services.docker_containers:
            for port in container.ports:
                if port.host_port and port.host_port not in covered_host_ports:
                    # Is it listening on a public interface?
                    is_public = port.host_ip == "0.0.0.0" or port.host_ip == "::"
                    
                    if is_public:
                        # DOCKER-2: Direct exposure
                        findings.append(Finding(
                            severity=Severity.WARNING,
                            confidence=0.9,
                            condition=f"Docker port {port.host_port} is exposed publicly bypassing Nginx",
                            cause=f"Container '{container.name}' publishes port {port.host_port} on {port.host_ip} but no Nginx proxy_pass covers it",
                            evidence=[Evidence(
                                source_file="docker",
                                line_number=1,
                                excerpt=f"Port Binding: {port.host_ip}:{port.host_port} -> {port.container_port}/{port.proto}",
                                command="docker ps"
                            )],
                            treatment=f"Bind to 127.0.0.1 instead: -p 127.0.0.1:{port.host_port}:{port.container_port}. Or secure via firewall.",
                            impact=["Bypasses Nginx authentication/rate-limits", "Direct attack surface exposure", "Potential for 'Shadow Routing'"]
                        ))
                    
        return findings

    def _check_socket_permissions(self) -> list[Finding]:
        """Check for docker.sock permission risks (DOCKER-RISK-1)."""
        findings: list[Finding] = []
        # This would require more stat info, but we can flag if we had permission issues earlier
        if self.model.services.docker.reason == "permission_denied":
            findings.append(Finding(
                severity=Severity.INFO,
                confidence=1.0,
                condition="Nginx Doctor has limited Docker visibility",
                cause="Access to /var/run/docker.sock was denied (Permission Denied)",
                evidence=[Evidence(
                    source_file="/var/run/docker.sock",
                    line_number=1,
                    excerpt="Permission Denied",
                    command="stat /var/run/docker.sock"
                )],
                treatment="Run Nginx Doctor as a user in the 'docker' group or use sudo.",
                impact=["Incomplete audit", "Missed containerized service correlations"]
            ))
        return findings

    def _get_correlations(self, entity_name: str) -> list:
        """Helper to find correlations for a container/process."""
        correlations = []
        if not hasattr(self.model, "projects"):
            return correlations
        for project in self.model.projects:
            for ev in project.correlation:
                if entity_name in ev.matched_entity:
                    correlations.append(ev)
        return correlations
