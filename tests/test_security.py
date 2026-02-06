"""Tests for Security Auditor."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from nginx_doctor.checks.security.security_auditor import SecurityAuditor
from nginx_doctor.model.server import ServerModel, NginxInfo, ServerBlock, LocationBlock
from nginx_doctor.checks import CheckContext

def test_security_audit_findings():
    """Verify security auditors detect missing headers and bad configs."""
    auditor = SecurityAuditor()
    
    # Mock Nginx Config
    server = ServerBlock(
        server_names=["example.com"],
        listen=["80"],
        autoindex=True, # Should trigger NGX-SEC-2
        headers={"X-XSS-Protection": "1; mode=block"}
    )
    
    # Missing: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options
    # These should trigger SEC-HEAD-1
    
    # NGX-SEC-3: Dotfile protection missing (no location matching \.)
    # The server setup below does NOT have a dotfile location, so NGX-SEC-3 SHOULD be in ids.
    
    # Actually, let's just use what the auditor expects.
    # SEC-HEAD-1: Missing headers
    # NGX-SEC-2: autoindex on
    # NGX-SEC-3: Dotfile protection missing (no location matching \.)
    # NGX-SEC-4: PHP in uploads (location /uploads { location ~ \.php })
    
    loc_uploads = LocationBlock(path="/uploads", source_file="/etc/nginx/nginx.conf")
    loc_php = LocationBlock(path="~ \\.php$", source_file="/etc/nginx/nginx.conf")
    loc_php.fastcgi_pass = "unix:/run/php/php-fpm.sock"
    loc_uploads.locations = [loc_php]
    
    server.locations = [loc_uploads]
    
    nginx_info = NginxInfo(version="1.18", config_path="/etc/nginx/nginx.conf")
    nginx_info.servers = [server]
    
    model = ServerModel(hostname="test")
    model.nginx = nginx_info
    
    ctx = CheckContext(model=model, ssh=None)
    
    findings = auditor.run(ctx)
    ids = [f.id for f in findings]
    print(f"DEBUG_IDS: {ids}")
    
    print(f"Findings: {ids}")
    # Verify expected IDs
    assert 'SEC-HEAD-1' in ids # Missing headers
    assert 'NGX-SEC-2' in ids     # Autoindex enabled
    assert 'NGX-SEC-3' in ids     # Dotfile protection missing
    assert 'NGX-SEC-4' in ids     # PHP in uploads
