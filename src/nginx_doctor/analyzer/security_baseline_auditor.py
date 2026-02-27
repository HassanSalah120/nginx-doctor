"""Security Baseline Auditor - SSH hardening and patch posture checks."""

from nginx_doctor.model.evidence import Evidence, Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import ServerModel


class SecurityBaselineAuditor:
    """Auditor for SSH and patch baseline signals."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        if not hasattr(self.model, "security_baseline"):
            return findings

        findings.extend(self._check_ssh_root_login())
        findings.extend(self._check_ssh_password_auth())
        findings.extend(self._check_pending_security_updates())
        findings.extend(self._check_reboot_required())
        return findings

    def _check_ssh_root_login(self) -> list[Finding]:
        value = (self.model.security_baseline.ssh_permit_root_login or "").lower()
        if value != "yes":
            return []

        return [
            Finding(
                id="SSH-1",
                severity=Severity.WARNING,
                confidence=0.95,
                condition="SSH root login is enabled",
                cause="`PermitRootLogin yes` allows direct root SSH authentication.",
                evidence=[
                    Evidence(
                        source_file="/etc/ssh/sshd_config",
                        line_number=1,
                        excerpt="PermitRootLogin yes",
                        command="sshd -T | grep permitrootlogin",
                    )
                ],
                treatment="Set `PermitRootLogin no` (or `prohibit-password` at minimum) and reload sshd.",
                impact=[
                    "Increases blast radius of credential compromise",
                    "Raises brute-force and privileged access risk",
                ],
            )
        ]

    def _check_ssh_password_auth(self) -> list[Finding]:
        value = (self.model.security_baseline.ssh_password_authentication or "").lower()
        if value not in {"yes", "on", "true"}:
            return []

        return [
            Finding(
                id="SSH-2",
                severity=Severity.WARNING,
                confidence=0.90,
                condition="SSH password authentication is enabled",
                cause="`PasswordAuthentication yes` allows password-based SSH login.",
                evidence=[
                    Evidence(
                        source_file="/etc/ssh/sshd_config",
                        line_number=1,
                        excerpt="PasswordAuthentication yes",
                        command="sshd -T | grep passwordauthentication",
                    )
                ],
                treatment="Prefer key-based auth: set `PasswordAuthentication no` and enforce SSH keys.",
                impact=[
                    "Higher brute-force risk compared to key-only SSH",
                    "Credential stuffing attacks become more viable",
                ],
            )
        ]

    def _check_pending_security_updates(self) -> list[Finding]:
        pending_security = self.model.security_baseline.pending_security_updates
        pending_total = self.model.security_baseline.pending_updates_total
        findings: list[Finding] = []

        if pending_security is not None and pending_security > 0:
            severity = Severity.CRITICAL if pending_security >= 20 else Severity.WARNING
            findings.append(
                Finding(
                    id="PATCH-1",
                    severity=severity,
                    confidence=0.85,
                    condition=f"{pending_security} pending security update(s) detected",
                    cause="System package metadata indicates unpatched security updates.",
                    evidence=[
                        Evidence(
                            source_file="package-manager",
                            line_number=1,
                            excerpt=f"security_updates={pending_security}, total_updates={pending_total}",
                            command="apt list --upgradable | grep -i security",
                        )
                    ],
                    treatment="Apply security updates in a maintenance window and restart affected services.",
                    impact=[
                        "Known vulnerabilities may remain exploitable",
                        "Higher incident and compliance risk",
                    ],
                )
            )
        elif pending_total is not None and pending_total > 50:
            findings.append(
                Finding(
                    id="PATCH-2",
                    severity=Severity.INFO,
                    confidence=0.70,
                    condition=f"{pending_total} package update(s) pending",
                    cause="Large backlog of pending package updates was detected.",
                    evidence=[
                        Evidence(
                            source_file="package-manager",
                            line_number=1,
                            excerpt=f"total_updates={pending_total}",
                            command="apt list --upgradable",
                        )
                    ],
                    treatment="Review update cadence and apply outstanding updates regularly.",
                    impact=[
                        "Operational drift from patched baseline",
                    ],
                )
            )

        return findings

    def _check_reboot_required(self) -> list[Finding]:
        if not self.model.security_baseline.reboot_required:
            return []

        severity = Severity.WARNING if (self.model.security_baseline.pending_security_updates or 0) > 0 else Severity.INFO
        return [
            Finding(
                id="PATCH-3",
                severity=severity,
                confidence=0.90,
                condition="System reboot required after updates",
                cause="Host indicates that a reboot is required to complete update activation.",
                evidence=[
                    Evidence(
                        source_file="/var/run/reboot-required",
                        line_number=1,
                        excerpt="reboot-required present",
                        command="test -f /var/run/reboot-required",
                    )
                ],
                treatment="Schedule and perform a controlled reboot to activate patched kernel/libraries.",
                impact=[
                    "Security fixes may not be fully active until reboot",
                ],
            )
        ]
