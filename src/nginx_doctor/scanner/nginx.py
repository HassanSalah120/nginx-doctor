"""Nginx Scanner - Collects nginx configuration and status.

This scanner runs nginx commands and collects raw configuration output.
Parsing is handled by the parser module.
"""

from dataclasses import dataclass

from nginx_doctor.connector.ssh import SSHConnector


@dataclass
class NginxScanResult:
    """Raw nginx scan results."""

    installed: bool = False
    version: str = ""
    config_path: str = ""
    full_config: str = ""  # Output of nginx -T
    test_result: str = ""  # Output of nginx -t
    test_passed: bool = False
    sites_enabled: list[str] | None = None
    sites_available: list[str] | None = None


class NginxScanner:
    """Scanner for Nginx configuration.

    Collects:
    - nginx version
    - Full configuration dump (nginx -T)
    - Configuration test results (nginx -t)
    - Sites enabled/available listings
    """

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> NginxScanResult:
        """Perform full nginx scan.

        Returns:
            NginxScanResult with all collected data.
        """
        result = NginxScanResult()

        # Check if nginx is installed
        version_result = self.ssh.run("nginx -v")
        if not version_result.success and not version_result.stderr:
            return result

        result.installed = True

        # Version is printed to stderr
        version_output = version_result.stderr or version_result.stdout
        if "nginx/" in version_output:
            result.version = version_output.split("nginx/")[1].split()[0].strip()

        # Get config path
        config_result = self.ssh.run("nginx -t")
        result.test_result = config_result.stderr or config_result.stdout
        result.test_passed = config_result.exit_code == 0

        # Extract config path from test output
        if "configuration file" in result.test_result:
            for line in result.test_result.split("\n"):
                if "configuration file" in line:
                    # nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
                    parts = line.split("configuration file")
                    if len(parts) > 1:
                        path = parts[1].strip().split()[0]
                        result.config_path = path
                        break

        # Get full configuration dump
        # This is the most important output - contains all includes resolved
        full_config_result = self.ssh.run("nginx -T")
        if full_config_result.success:
            result.full_config = full_config_result.stdout
        else:
            # nginx -T also outputs to stderr on some systems
            result.full_config = full_config_result.stderr or ""

        # List sites-enabled and sites-available
        result.sites_enabled = self.list_sites("/etc/nginx/sites-enabled")
        result.sites_available = self.list_sites("/etc/nginx/sites-available")

        return result

    def list_sites(self, path: str = "/etc/nginx/sites-enabled") -> list[str]:
        """List files in a sites directory."""
        if not self.ssh.dir_exists(path):
            return []

        files = self.ssh.list_dir(path)
        return [f for f in files if not f.startswith(".")]

    def get_all_roots(self, nginx_info: "NginxInfo") -> tuple[list[str], list[str]]:
        """Extract unique root/alias directories, filtering out dynamic paths.
        
        Returns:
            Tuple of (valid_paths, dynamic_variables)
        """
        paths = set()
        variables = set()
        
        for server in nginx_info.servers:
            # Server-level root
            if server.root:
                if self._is_dynamic_path(server.root):
                    variables.add(f"root: {server.root}")
                else:
                    paths.add(self._normalize_project_path(server.root))
            
            # Location-level root and alias
            for loc in server.locations:
                if loc.root:
                    if self._is_dynamic_path(loc.root):
                        variables.add(f"root: {loc.root}")
                    else:
                        paths.add(self._normalize_project_path(loc.root))
                if loc.alias:
                    if self._is_dynamic_path(loc.alias):
                        variables.add(f"alias: {loc.alias}")
                    else:
                        paths.add(self._normalize_project_path(loc.alias))
        
        # Filter out obvious system paths
        system_paths = {"/etc/nginx", "/var/log", "/run", "/tmp", "/dev"}
        filtered_paths = [
            p for p in paths 
            if p and p != "/" and not any(p.startswith(s) for s in system_paths)
        ]
        
        return list(set(filtered_paths)), sorted(list(variables))

    def _is_dynamic_path(self, path: str) -> bool:
        """Check if a path contains nginx variables or regex captures."""
        dynamic_indicators = ["$", "*", "(", ")", "{", "}"]
        return any(indicator in path for indicator in dynamic_indicators)

    def _normalize_project_path(self, path: str) -> str:
        """Strip internal sub-paths (public, storage, etc.) to reach the project root.
        
        This prevents Nginx aliases for storage or cache from being treated
        as standalone project roots.
        """
        path = path.strip().rstrip("/")
        
        # Patterns to walk up from
        sub_paths = [
            "/public",
            "/storage/app",
            "/storage/logs",
            "/storage",
            "/bootstrap/cache",
            "/bootstrap",
        ]
        
        # Iteratively strip suffixes to handle nested cases
        changed = True
        while changed:
            changed = False
            for p in sub_paths:
                if path.endswith(p):
                    path = path[:-len(p)]
                    changed = True
                    break
        
        return path or "/"

    def get_active_connections(self) -> int | None:
        """Get number of active nginx connections."""
        # Try to get from nginx status module if enabled
        result = self.ssh.run("curl -s http://127.0.0.1/nginx_status 2>/dev/null | head -1")
        if result.success and "Active connections:" in result.stdout:
            try:
                return int(result.stdout.split(":")[1].strip())
            except (IndexError, ValueError):
                pass
        return None
