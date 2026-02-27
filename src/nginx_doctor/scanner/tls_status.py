"""TLS Status Scanner - live TLS inspection using openssl s_client + SNI."""

from __future__ import annotations

import datetime
import re

from nginx_doctor.connector.ssh import SSHConnector
from nginx_doctor.model.server import NginxInfo, TLSCertificateStatus, TLSStatusModel


class TLSStatusScanner:
    """Collect TLS metadata from live handshake rather than file parsing."""

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self, nginx_info: NginxInfo | None) -> TLSStatusModel:
        if not nginx_info:
            return TLSStatusModel()
        sni_targets = self._collect_sni_targets(nginx_info)
        certs: list[TLSCertificateStatus] = []
        for sni, connect_port in sni_targets:
            certs.append(self._inspect_live_cert(sni, connect_port))
        return TLSStatusModel(certificates=certs)

    def _collect_sni_targets(self, nginx_info: NginxInfo) -> list[tuple[str, int]]:
        targets: set[tuple[str, int]] = set()
        for server in nginx_info.servers:
            listens = [self._extract_listen_port(v) for v in (server.listen or [])]
            ssl_like = server.ssl_enabled or any("ssl" in (l or "").lower() for l in (server.listen or []))
            if not ssl_like and not any(p == 443 for p in listens if p is not None):
                continue
            port = next((p for p in listens if p), 443) or 443
            for name in (server.server_names or []):
                sni = (name or "").strip()
                if not sni or sni in {"_", "default"} or sni.startswith("*"):
                    continue
                targets.add((sni, port))
        return sorted(targets)

    def _inspect_live_cert(self, sni: str, port: int) -> TLSCertificateStatus:
        connect = f"127.0.0.1:{port}"
        path = f"live://{sni}@{connect}"
        status = TLSCertificateStatus(path=path)
        cmd = (
            "sh -lc \""
            f"echo | openssl s_client -servername {sni} -connect {connect} 2>/dev/null "
            "| openssl x509 -noout -issuer -subject -enddate -ext subjectAltName 2>/dev/null\""
        )
        res = self.ssh.run(cmd, timeout=8)
        if not res.success or not (res.stdout or "").strip():
            status.parse_ok = False
            return status

        lines = [line.strip() for line in (res.stdout or "").splitlines() if line.strip()]
        for line in lines:
            if line.startswith("issuer="):
                status.issuer = line[len("issuer=") :].strip()
            elif line.startswith("subject="):
                status.subject = line[len("subject=") :].strip()
            elif line.startswith("notAfter="):
                status.expires_at = line[len("notAfter=") :].strip()
            elif "DNS:" in line:
                sans = [s.strip().replace("DNS:", "") for s in line.split(",") if "DNS:" in s]
                status.sans.extend([s for s in sans if s])
        status.days_remaining = self._days_until_expiry(status.expires_at)
        status.parse_ok = True
        return status

    def _days_until_expiry(self, expires: str | None) -> int | None:
        if not expires:
            return None
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                dt = datetime.datetime.strptime(expires, fmt).replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                return max(0, int((dt - now).total_seconds() // 86400))
            except ValueError:
                continue
        return None

    @staticmethod
    def _extract_listen_port(listen: str) -> int | None:
        value = (listen or "").split()[0]
        if "]:" in value:
            value = value.rsplit("]:", 1)[1]
        elif ":" in value and not value.startswith("["):
            value = value.rsplit(":", 1)[1]
        return int(value) if value.isdigit() else None
