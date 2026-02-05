"""Nginx Doctor Analyzer - Diagnoses nginx configuration problems.

This is the core diagnostic engine that identifies misconfigurations
and generates evidence-based findings.

IMPORTANT: All findings MUST include evidence with:
- source_file
- line_number  
- excerpt
"""

from nginx_doctor.model.evidence import Evidence, Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import (
    NginxInfo,
    ProjectInfo,
    ProjectType,
    ServerBlock,
    ServerModel,
)


class NginxDoctorAnalyzer:
    """Diagnoses nginx configuration problems.

    This analyzer NEVER runs shell commands.
    It only reasons about the ServerModel built by scanners and parsers.
    """

    def __init__(self, model: ServerModel, raw_config: str = "") -> None:
        """Initialize with a server model.

        Args:
            model: The complete server model.
            raw_config: Raw nginx -T output for evidence extraction.
        """
        self.model = model
        self.raw_config = raw_config

    def diagnose(self, additional_findings: list[Finding] | None = None) -> list[Finding]:
        """Run all diagnostic checks and group related findings."""
        findings: list[Finding] = []
        if additional_findings:
            findings.extend(additional_findings)

        if not self.model.nginx:
            return findings

        # 1. Run each diagnostic check with assigned IDs
        findings.extend(self._check_backup_configs())
        findings.extend(self._check_laravel_roots())
        findings.extend(self._check_dynamic_nginx_paths())
        findings.extend(self._check_missing_try_files())
        findings.extend(self._check_php_socket_mismatch())
        findings.extend(self._check_duplicate_server_names())
        findings.extend(self._check_default_sites_enabled())
        findings.extend(self._check_php_version_consistency())
        
        # Rule ID map
        rule_map = {
            "Backup configuration": "NGX001",
            "Duplicate server_name": "NGX002",
            "PHP-FPM socket not found": "NGX003",
            "Laravel root misconfigured": "NGX004",
            "Missing try_files": "NGX005",
            "Nginx config variables": "NGX006",
            "sites-enabled only contains symlinks": "NGX007",
            "Default nginx site still enabled": "NGX008",
            "Multiple PHP versions installed": "NGX100",
            "Mixed PHP versions in use": "NGX101",
            ".env file may be exposed": "NGX200",
            "Port 443 without SSL directive": "NGX201",
            "SSL enabled without certificate": "NGX202",
        }
        
        # 2. Assign Rule IDs and Deduplicate
        deduped: list[Finding] = []
        seen_keys: dict[tuple[str, str], Finding] = {} # (rule_id, condition) -> Finding
        
        for f in findings:
            fid = "NGX000"
            for pattern, rid in rule_map.items():
                if pattern in f.condition:
                    fid = rid
                    break
            
            key = (fid, f.condition)
            if key in seen_keys:
                # Merge evidence into existing finding
                base = seen_keys[key]
                for ev in f.evidence:
                    # Check for exact evidence duplicate
                    if not any(e.source_file == ev.source_file and e.line_number == ev.line_number for e in base.evidence):
                        base.evidence.append(ev)
            else:
                f.id = fid # Provisional ID
                seen_keys[key] = f
                deduped.append(f)
        
        findings = deduped

        # 3. Instance counters for unique IDs (e.g., NGX002-1, NGX002-2)
        instance_counters: dict[str, int] = {}
        for f in findings:
            rule_id = f.id
            instance_counters[rule_id] = instance_counters.get(rule_id, 0) + 1
            f.id = f"{rule_id}-{instance_counters[rule_id]}"
        
        # 4. ROOT CAUSE CHAINING: 
        # If we have backup configs (NGX001), link and downgrade duplicate server_name (NGX002) findings.
        backup_findings = [f for f in findings if f.id.startswith("NGX001")]
        if backup_findings:
            backup_files = set()
            for bf in backup_findings:
                backup_files.update({ev.source_file for ev in bf.evidence if ev.source_file != "nginx.conf"})
            
            for f in findings:
                if f.id.startswith("NGX002"):
                    # Check if any evidence for this duplicate comes from a backup file
                    from_backup = any(ev.source_file in backup_files for ev in f.evidence)
                    
                    if from_backup:
                        # Mark as derived from first backup finding (Rule hierarchy)
                        f.derived_from = "NGX001"
                        f.severity = Severity.INFO
                        # Cleaner condition
                        f.cause = f"{f.cause}. This is a side-effect of backup files being enabled (NGX001)."
                        f.treatment = "Resolve primary finding NGX001: 'Backup configuration files are enabled'."
        
        return findings

    def _check_php_version_consistency(self) -> list[Finding]:
        """Check if multiple PHP versions are installed when only one might be needed."""
        findings: list[Finding] = []
        if not self.model.php or len(self.model.php.versions) <= 1:
            return findings
            
        findings.append(
            Finding(
                severity=Severity.INFO,
                confidence=0.8,
                condition="Multiple PHP versions installed",
                cause=f"Server has {', '.join(self.model.php.versions)} installed",
                evidence=[Evidence(source_file="/usr/bin/php", line_number=1, excerpt=f"Default CLI: PHP {self.model.php.versions[0]}", command="php -v")],
                treatment="Consider removing unused PHP versions to reduce attack surface and disk usage",
                impact=["Unnecessary disk space usage", "Security maintenance overhead"]
            )
        )
        return findings

    def _check_dynamic_nginx_paths(self) -> list[Finding]:
        """Identify Nginx variables or regex captures in config directives.
        
        These are often mistaken for filesystem paths but are actually 
        dynamic variables (e.g., $1, $host).
        """
        findings: list[Finding] = []
        if not self.model.nginx or not self.model.nginx.skipped_paths:
            return findings

        findings.append(
            Finding(
                severity=Severity.INFO,
                confidence=1.0,
                condition="Nginx config variables detected in roots",
                cause=(
                    "Nginx 'root' or 'alias' directives contain dynamic variables or regex captures "
                    "(e.g., $1, $domain). These are not real filesystem paths."
                ),
                evidence=[
                    Evidence(
                        source_file="nginx.conf",
                        line_number=1,
                        excerpt=path,
                        command="nginx -T",
                    )
                    for path in self.model.nginx.skipped_paths
                ],
                treatment=(
                    "These are not real filesystem paths; they appear to be regex capture references "
                    "(e.g., rewrite $1). Nginx-Doctor ignores them and avoids treating them as project roots."
                ),
                impact=[
                    "Scanner avoids scanning non-existent dynamic directories",
                    "Cleaner project discovery results",
                ],
            )
        )

        return findings

    def _check_laravel_roots(self) -> list[Finding]:
        """Check if Laravel projects have correct root pointing to /public."""
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        # Get Laravel projects
        laravel_projects = [
            p for p in self.model.projects if p.type == ProjectType.LARAVEL
        ]

        for project in laravel_projects:
            expected_root = project.public_path or f"{project.path}/public"

            # Find server blocks that might be for this project
            for server in self.model.nginx.servers:
                if not server.root:
                    continue

                # Check if this server is for this project
                if project.path in server.root and "/public" not in server.root:
                    # Root is pointing to project root, not public
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            confidence=0.95,
                            condition="Laravel root misconfigured",
                            cause=f"root points to '{server.root}' instead of '{expected_root}'",
                            evidence=[
                                Evidence(
                                    source_file=server.source_file,
                                    line_number=server.line_number,
                                    excerpt=f"root {server.root}",
                                    command="nginx -T",
                                )
                            ],
                            treatment=f"Change root to '{expected_root}'",
                            impact=[
                                "Assets may fail to load",
                                "Sensitive files may be exposed",
                                "Laravel routing will break",
                            ],
                        )
                    )

        return findings

    def _check_missing_try_files(self) -> list[Finding]:
        """Check for PHP locations missing try_files directive."""
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        for server in self.model.nginx.servers:
            for location in server.locations:
                # Check if this is a PHP location
                if location.fastcgi_pass and not location.try_files:
                    findings.append(
                        Finding(
                            severity=Severity.WARNING,
                            confidence=0.85,
                            condition="Missing try_files in PHP location",
                            cause="PHP location has no try_files fallback for routing",
                            evidence=[
                                Evidence(
                                    source_file=server.source_file,
                                    line_number=location.line_number,
                                    excerpt=f"location {location.path}",
                                    command="nginx -T",
                                )
                            ],
                            treatment="Add: try_files $uri $uri/ /index.php?$query_string;",
                            impact=[
                                "Pretty URLs may not work",
                                "Framework routing may fail",
                            ],
                        )
                    )

        return findings

    def _check_php_socket_mismatch(self) -> list[Finding]:
        """Check if fastcgi_pass points to existing PHP-FPM sockets."""
        findings: list[Finding] = []

        if not self.model.nginx or not self.model.php:
            return findings

        available_sockets = set(self.model.php.sockets)

        for server in self.model.nginx.servers:
            for location in server.locations:
                if not location.fastcgi_pass:
                    continue

                # Check if it's a unix socket
                if location.fastcgi_pass.startswith("unix:"):
                    socket_path = location.fastcgi_pass.replace("unix:", "").strip()
                    if socket_path not in available_sockets:
                        findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                confidence=0.90,
                                condition="PHP-FPM socket not found",
                                cause=f"fastcgi_pass points to '{socket_path}' which doesn't exist",
                                evidence=[
                                    Evidence(
                                        source_file=server.source_file,
                                        line_number=location.line_number,
                                        excerpt=f"fastcgi_pass {location.fastcgi_pass}",
                                        command="nginx -T",
                                    )
                                ],
                                treatment=f"Update to an available socket: {', '.join(available_sockets) or 'none found'}",
                                impact=[
                                    "PHP will not work at all",
                                    "502 Bad Gateway errors",
                                ],
                            )
                        )

        return findings

    def _check_duplicate_server_names(self) -> list[Finding]:
        """Check for duplicate server_name declarations.
        
        Groups all occurrences of the same name into a single finding.
        """
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        # Collect all server blocks per server_name
        name_to_servers: dict[str, list[ServerBlock]] = {}
        
        for server in self.model.nginx.servers:
            for name in server.server_names:
                if name not in name_to_servers:
                    name_to_servers[name] = []
                name_to_servers[name].append(server)

        # Create one finding per duplicated name (with all occurrences as evidence)
        for name, servers in name_to_servers.items():
            if len(servers) <= 1:
                continue  # Not a duplicate
            
            evidence_list = [
                Evidence(
                    source_file=s.source_file,
                    line_number=s.line_number,
                    excerpt=f"server_name {' '.join(s.server_names)}",
                    command="nginx -T",
                )
                for s in servers
            ]
            
            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    confidence=0.95,
                    condition=f"Duplicate server_name '{name}'",
                    cause=f"Found {len(servers)} declarations across different blocks",
                    evidence=evidence_list,
                    treatment="Remove or rename duplicate server blocks to prevent shadowing",
                    impact=[
                        "Unpredictable request routing",
                        "One configuration may shadow the other",
                    ],
                )
            )

        return findings

    def _check_backup_configs(self) -> list[Finding]:
        """Check for backup files in active configuration directories.
        
        Nginx often includes everything in /etc/nginx/sites-enabled/*,
        including .bak, .old, or .swp files.
        """
        findings: list[Finding] = []
        if not self.model.nginx:
            return findings

        backup_patterns = [".bak", ".old", ".save", ".orig", ".dpkg-dist", ".swp", "~"]
        backup_files: list[str] = []

        # Check all included files
        for file_path in self.model.nginx.includes:
            if "/sites-enabled/" in file_path and any(p in file_path for p in backup_patterns):
                backup_files.append(file_path)

        if backup_files:
            evidence = []
            # Premium: Add the include directive that caused this (Root Cause Evidence)
            if "include /etc/nginx/sites-enabled/*" in self.raw_config:
                evidence.append(
                    Evidence(
                        source_file="nginx.conf",
                        line_number=1,
                        excerpt="include /etc/nginx/sites-enabled/*;",
                        command="nginx -T",
                    )
                )
            
            evidence.extend([
                Evidence(
                    source_file=f,
                    line_number=1,
                    excerpt="File matched backup pattern and is in sites-enabled",
                    command="ls /etc/nginx/sites-enabled",
                )
                for f in backup_files
            ])

            # Generate actionable commands
            move_cmds = [f"sudo mv {f} /etc/nginx/backups/" for f in backup_files]
            treatment = (
                "Move backups out of include paths to a dedicated folder:\n"
                "sudo mkdir -p /etc/nginx/backups\n" +
                "\n".join(move_cmds) +
                "\nsudo nginx -t && sudo systemctl reload nginx"
            )

            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    confidence=1.0,
                    condition="Backup configuration files are enabled",
                    cause=f"Found {len(backup_files)} backup/temp files being loaded by Nginx in sites-enabled",
                    evidence=evidence,
                    treatment=treatment,
                    impact=[
                        "Duplicate server_name conflicts (Real cause of many warnings)",
                        "Unexpected configuration behavior",
                        "Security risk if old configs are exposed",
                    ],
                )
            )

        return findings

    def _check_sites_enabled_structure(self) -> list[Finding]:
        """Verify that sites-enabled only contains symlinks, not flat files."""
        findings: list[Finding] = []
        return findings

    def _check_default_sites_enabled(self) -> list[Finding]:
        """Check if default nginx sites are still enabled."""
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        for server in self.model.nginx.servers:
            if server.is_default_server and "default" in server.source_file:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        confidence=0.80,
                        condition="Default nginx site still enabled",
                        cause="The default nginx site configuration is active",
                        evidence=[
                            Evidence(
                                source_file=server.source_file,
                                line_number=server.line_number,
                                excerpt="server { ... }",
                                command="nginx -T",
                            )
                        ],
                        treatment=(
                            f"Consider disabling:\nsudo rm {server.source_file}\n"
                            "sudo nginx -t && sudo systemctl reload nginx"
                        ),
                        impact=[
                            "May catch requests meant for other sites",
                            "Exposes default nginx page",
                        ],
                    )
                )

        return findings
