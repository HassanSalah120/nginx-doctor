"""Security Auditor.

Checks for common security misconfigurations and best practices.

Checks:
- SEC-HEAD-1: Missing Security Headers (X-Frame, X-Content, HSTS, etc.)
- NGX-SEC-2: autoindex is enabled (directory listing prevention)
- NGX-SEC-3: Dotfile protection is missing (/.git, .env handling)
- NGX-SEC-4: PHP execution allowed in uploads directory
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from nginx_doctor.checks import BaseCheck, CheckContext, register_check
from nginx_doctor.model.evidence import Evidence, Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import LocationBlock, ServerBlock

if TYPE_CHECKING:
    from nginx_doctor.model.server import NginxInfo


@register_check
class SecurityAuditor(BaseCheck):
    """Auditor for security settings."""
    
    @property
    def category(self) -> str:
        return "security"
    
    @property
    def requires_ssh(self) -> bool:
        return False  # Works on parsed model
    
    def run(self, context: CheckContext) -> list[Finding]:
        """Run security checks."""
        findings: list[Finding] = []
        
        if not context.model.nginx:
            return []
            
        info = context.model.nginx
        findings.extend(self._check_security_headers(info))
        findings.extend(self._check_autoindex(info))
        findings.extend(self._check_dotfile_protection(info))
        findings.extend(self._check_php_in_uploads(info))
        
        return findings

    def _get_all_locations(self, location: LocationBlock) -> list[LocationBlock]:
        """Recursively get all nested locations."""
        locs = [location]
        for nested in location.locations:
            locs.extend(self._get_all_locations(nested))
        return locs
        
    def _iter_all_locations(self, info: "NginxInfo") -> list[tuple[ServerBlock, LocationBlock]]:
        """Utility to iterate all (server, location) pairs including nested ones."""
        pairs = []
        for server in info.servers:
            # print(f"DEBUG_SEC: server {server.server_names} has {len(server.locations)} locations")
            for loc in server.locations:
                all_locs = self._get_all_locations(loc)
                # print(f"DEBUG_SEC: loc {loc.path} expanded to {len(all_locs)} items")
                for nested in all_locs:
                    pairs.append((server, nested))
        print(f"DEBUG_SEC: total pairs: {len(pairs)}")
        return pairs
    
    def _check_security_headers(self, info: "NginxInfo | None") -> list[Finding]:
        """SEC-HEAD-1: Check for essential security headers with inheritance logic."""
        if not info:
            return []
            
        findings = []
        
        required_headers = {
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer-when-downgrade",  # or stricter
            # HSTS is special (HTTPS only), processed separately potentially
        }
        
        for server, location in self._iter_all_locations(info):
            # For each location, verify effective headers
            # Determine effective headers for this scope
            effective_headers = self._get_effective_headers(info, server, location)
                
            missing = []
            for name, _ in required_headers.items():
                # Check keys case-insensitively
                if not any(k.lower() == name.lower() for k in effective_headers):
                    missing.append(name)
            
            if missing:
                # Construct nice evidence using inheritance info
                # Show where headers ARE defined to explain why they were lost
                evidence_list = []
                
                # Show definition site of current effective headers
                if location.headers:
                    evidence_list.append(Evidence(
                        source_file=info.config_path, # approximated
                        line_number=location.line_number,
                        excerpt=f"Location '{location.path}' defines add_header, clearing parent headers",
                        command="",
                    ))
                elif server.headers:
                    pass # inherited from server, which is fine if server has them
                
                findings.append(Finding(
                    id="SEC-HEAD-1",
                    severity=Severity.WARNING,
                    confidence=0.9,
                    condition=f"Missing security headers in location '{location.path}'",
                    cause=(
                        f"The following headers are missing: {', '.join(missing)}. "
                        "Note: Nginx 'add_header' in a child block clears all parent headers."
                    ),
                    evidence=[Evidence(
                        source_file=server.source_file,
                        line_number=location.line_number,
                        excerpt=f"Location: {location.path}",
                        command="",
                    )] + evidence_list,
                    treatment=(
                        "Add missing headers directly to this block or ensure no `add_header` "
                        "directive overrides the include file."
                    ),
                    impact=[
                        "Clickjacking attacks (X-Frame-Options)",
                        "MIME-sniffing attacks (X-Content-Type-Options)",
                        "Information leakage (Referrer-Policy)",
                    ],
                ))
                    
        return findings

    def _get_effective_headers(
        self, info: "NginxInfo", server: ServerBlock, location: LocationBlock
    ) -> dict[str, str]:
        """Calculate effective headers based on Nginx inheritance rules.
        
        Rule: Directives from the preceding level are inherited ONLY if there are 
        no add_header directives defined on the current level.
        """
        # Level 3: Location
        if location.headers:
            return location.headers
            
        # Level 2: Server
        if server.headers:
            return server.headers
            
        # Level 1: HTTP/Global
        if info.http_headers:
            return info.http_headers
            
        return {}

    def _check_autoindex(self, info: "NginxInfo | None") -> list[Finding]:
        """NGX-SEC-2: Check for autoindex on."""
        if not info:
            return []
            
        findings = []
        for server in info.servers:
            if server.autoindex:
                findings.append(Finding(
                    id="NGX-SEC-2",
                    severity=Severity.WARNING,
                    confidence=1.0,
                    condition=f"Directory listing (autoindex) enabled on {server.server_names}",
                    cause="The 'autoindex on;' directive is present in the server block.",
                    evidence=[Evidence(
                        source_file=server.source_file,
                        line_number=server.line_number,
                        excerpt="autoindex on;",
                        command="",
                    )],
                    treatment="Disable autoindex: 'autoindex off;' or remove the directive.",
                    impact=["Sensitive files in the web root may be disclosed to attackers."],
                ))
        return findings

    def _check_dotfile_protection(self, info: "NginxInfo | None") -> list[Finding]:
        """NGX-SEC-3: Check if dotfiles are blocked."""
        if not info:
            return []
            
        findings = []
        
        for server in info.servers:
            has_dotfile_block = False
            
            for location in server.locations:
                # Look for locations matching /\. or ~ /\\.
                # Common pattern: location ~ /\.
                if r"/\." in location.path or r"\." in location.path:
                    # Check if it denies all
                    # We don't have 'deny all' parsed yet. 
                    # But we can check if a "location ~ /\\. {" exists at all.
                    has_dotfile_block = True
                    break
            
            if not has_dotfile_block:
                # Only warn if it's a default server or has valid server_names
                findings.append(Finding(
                    id="NGX-SEC-3",
                    severity=Severity.WARNING,
                    confidence=0.8,
                    condition=f"Server {server.server_names} missing dotfile protection",
                    cause="No location block detected targeting dotfiles (e.g., location ~ /\\.).",
                    evidence=[Evidence(
                        source_file=server.source_file,
                        line_number=server.line_number,
                        excerpt="server { ... }",
                        command="",
                    )],
                    treatment=(
                        "Add dotfile protection:\n"
                        "    location ~ /\\. {\n"
                        "        deny all;\n"
                        "    }"
                    ),
                    impact=[
                        "Sensitive files like .env, .git/ may be publicly accessible",
                    ],
                ))
        
        return findings

    def _check_php_in_uploads(self, info: "NginxInfo | None") -> list[Finding]:
        """NGX-SEC-4: Check if PHP execution is supposedly blocked in uploads."""
        if not info:
            return []
            
        findings = []
        risky_keywords = ["upload", "storage", "public/media", "wp-content/uploads"]
        
        def check_recursive(location: LocationBlock, in_uploads: bool):
            current_is_uploads = in_uploads or any(k in location.path for k in risky_keywords)
            
            if current_is_uploads and location.fastcgi_pass:
                findings.append(Finding(
                    id="NGX-SEC-4",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    condition=f"PHP execution enabled in uploads directory: {location.path}",
                    cause=f"Location '{location.path}' contains fastcgi_pass directive.",
                    evidence=[Evidence(
                        source_file=info.config_path, 
                        line_number=location.line_number,
                        excerpt=f"fastcgi_pass {location.fastcgi_pass}",
                        command="",
                    )],
                    treatment=(
                        "Remove PHP execution from upload directories.\n"
                        "Ensure: location ... { try_files $uri =404; }"
                    ),
                    impact=[
                        "Malicious PHP scripts uploaded by users can be executed",
                        "Full server compromise (webshell risks)",
                    ],
                ))
            
            for nested in location.locations:
                check_recursive(nested, current_is_uploads)

        for server in info.servers:
            for location in server.locations:
                check_recursive(location, False)
                    
        return findings
