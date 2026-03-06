"""Resources Auditor - Interprets runtime pressure and process hotspots."""

from __future__ import annotations

import re

from nginx_doctor.engine.runtime_thresholds import env_float, env_int
from nginx_doctor.model.evidence import Evidence, Severity
from nginx_doctor.model.finding import Finding
from nginx_doctor.model.server import ServerModel


class ResourcesAuditor:
    """Auditor for OOM/PSI/process-pressure signals."""

    _PS_RE = re.compile(r"^\s*(\d+)\s+(\S+)\s+([0-9.]+)\s+([0-9.]+)")
    _NOISE_PROCESSES = {"ps", "sudo", "head", "grep", "sh", "bash"}

    def __init__(self, model: ServerModel) -> None:
        self.model = model
        self._oom_crit = env_int("NGINX_DOCTOR_OOM_CRIT_COUNT", 3, min_value=1, max_value=200)
        self._psi_mem_warn = env_float("NGINX_DOCTOR_RESOURCES_PSI_MEM_WARN", 2.0, min_value=0.1, max_value=100.0)
        self._psi_mem_crit = env_float("NGINX_DOCTOR_RESOURCES_PSI_MEM_CRIT", 6.0, min_value=self._psi_mem_warn, max_value=100.0)
        self._psi_io_warn = env_float("NGINX_DOCTOR_RESOURCES_PSI_IO_WARN", 2.0, min_value=0.1, max_value=100.0)
        self._psi_io_crit = env_float("NGINX_DOCTOR_RESOURCES_PSI_IO_CRIT", 6.0, min_value=self._psi_io_warn, max_value=100.0)
        self._psi_cpu_warn = env_float("NGINX_DOCTOR_RESOURCES_PSI_CPU_WARN", 20.0, min_value=0.1, max_value=100.0)
        self._cpu_hotspot_pct = env_float("NGINX_DOCTOR_RESOURCES_CPU_HOTSPOT_PERCENT", 85.0, min_value=1.0, max_value=100.0)
        self._mem_hotspot_pct = env_float("NGINX_DOCTOR_RESOURCES_MEM_HOTSPOT_PERCENT", 70.0, min_value=1.0, max_value=100.0)

    def audit(self) -> list[Finding]:
        if not hasattr(self.model, "resources"):
            return []

        findings: list[Finding] = []
        findings.extend(self._check_oom_events())
        findings.extend(self._check_pressure_stall())
        findings.extend(self._check_top_offenders())
        return findings

    def _check_oom_events(self) -> list[Finding]:
        oom = self.model.resources.oom_events_24h
        if oom is None or oom <= 0:
            return []

        severity = Severity.CRITICAL if oom >= self._oom_crit else Severity.WARNING
        return [
            Finding(
                id="RES-1",
                severity=severity,
                confidence=0.9,
                condition=f"Runtime OOM pressure detected ({oom} event(s) in last 24h)",
                cause="Resource scanner observed out-of-memory kill signatures in recent logs.",
                evidence=[
                    Evidence(
                        source_file="journalctl",
                        line_number=1,
                        excerpt=f"oom_events_24h={oom}",
                        command="journalctl --since '24 hours ago' | egrep -i 'oom-kill|out of memory'",
                    )
                ],
                treatment="Lower memory pressure and set safer per-service memory/concurrency limits.",
                impact=[
                    "Critical processes can be terminated under load",
                ],
            )
        ]

    def _check_pressure_stall(self) -> list[Finding]:
        cpu = self.model.resources.psi_cpu_some_avg10
        mem = self.model.resources.psi_memory_some_avg10
        io = self.model.resources.psi_io_some_avg10
        if cpu is None and mem is None and io is None:
            return []

        risk = []
        if mem is not None and mem >= self._psi_mem_warn:
            risk.append(f"memory={mem:.2f}")
        if io is not None and io >= self._psi_io_warn:
            risk.append(f"io={io:.2f}")
        if cpu is not None and cpu >= self._psi_cpu_warn:
            risk.append(f"cpu={cpu:.2f}")
        if not risk:
            return []

        severity = Severity.CRITICAL if any(token.startswith(("memory=", "io=")) for token in risk) and (
            (mem or 0) >= self._psi_mem_crit or (io or 0) >= self._psi_io_crit
        ) else Severity.WARNING

        return [
            Finding(
                id="RES-2",
                severity=severity,
                confidence=0.76,
                condition="Linux pressure stall indicators are elevated",
                cause=f"PSI avg10 values indicate contention: {', '.join(risk)}.",
                evidence=[
                    Evidence(
                        source_file="/proc/pressure/*",
                        line_number=1,
                        excerpt=f"cpu={cpu}, memory={mem}, io={io}",
                        command="cat /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io",
                    )
                ],
                treatment="Investigate workload contention and tune limits/capacity for CPU, memory, and storage paths.",
                impact=[
                    "Tail latency and timeout risk increase during bursts",
                ],
            )
        ]

    def _check_top_offenders(self) -> list[Finding]:
        cpu_row = self._parse_top_row(self.model.resources.top_cpu_processes[:1])
        mem_row = self._parse_top_row(self.model.resources.top_mem_processes[:1])
        if cpu_row is not None and cpu_row[1] in self._NOISE_PROCESSES:
            cpu_row = None
        if mem_row is not None and mem_row[1] in self._NOISE_PROCESSES:
            mem_row = None
        if cpu_row is None and mem_row is None:
            return []

        notes: list[str] = []
        evidence_lines: list[str] = []
        if cpu_row is not None:
            _, proc, cpu_pct, _ = cpu_row
            evidence_lines.append(f"cpu_top={proc}({cpu_pct:.1f}%)")
            if cpu_pct >= self._cpu_hotspot_pct:
                notes.append(f"CPU hotspot: {proc} {cpu_pct:.1f}%")
        if mem_row is not None:
            _, proc, _, mem_pct = mem_row
            evidence_lines.append(f"mem_top={proc}({mem_pct:.1f}%)")
            if mem_pct >= self._mem_hotspot_pct:
                notes.append(f"Memory hotspot: {proc} {mem_pct:.1f}%")

        if not notes:
            return []

        severity = Severity.WARNING
        return [
            Finding(
                id="RES-3",
                severity=severity,
                confidence=0.72,
                condition="Top process resource hotspots detected",
                cause="One or more processes dominate CPU or memory usage.",
                evidence=[
                    Evidence(
                        source_file="ps",
                        line_number=1,
                        excerpt="; ".join(evidence_lines),
                        command="ps -eo pid,comm,%cpu,%mem --sort=-%cpu; ps -eo pid,comm,%cpu,%mem --sort=-%mem",
                    )
                ],
                treatment="Profile and tune hotspot processes or adjust service limits/scaling.",
                impact=[
                    "Resource contention can degrade overall host responsiveness",
                ],
            )
        ]

    def _parse_top_row(self, rows: list[str]) -> tuple[int, str, float, float] | None:
        for row in rows:
            match = self._PS_RE.match(row)
            if not match:
                continue
            try:
                pid = int(match.group(1))
                proc = match.group(2)
                cpu_pct = float(match.group(3))
                mem_pct = float(match.group(4))
                return (pid, proc, cpu_pct, mem_pct)
            except ValueError:
                continue
        return None
