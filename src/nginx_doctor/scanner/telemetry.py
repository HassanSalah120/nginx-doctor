"""Telemetry Scanner - Collects host-level performance telemetry.

This scanner gathers lightweight OS metrics that are useful for
infrastructure health checks:
- CPU cores and load average
- Memory and swap usage
- Disk usage by mountpoint
"""

from nginx_doctor.connector.ssh import SSHConnector
from nginx_doctor.model.server import DiskUsage, TelemetryModel


class TelemetryScanner:
    """Scanner for host telemetry snapshots."""

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> TelemetryModel:
        """Collect telemetry data from the host."""
        telemetry = TelemetryModel()
        self._collect_cpu_load(telemetry)
        self._collect_memory_swap(telemetry)
        self._collect_disks(telemetry)
        return telemetry

    def _collect_cpu_load(self, telemetry: TelemetryModel) -> None:
        nproc_res = self.ssh.run("nproc 2>/dev/null")
        if nproc_res.success and nproc_res.stdout.strip().isdigit():
            telemetry.cpu_cores = int(nproc_res.stdout.strip())

        load_res = self.ssh.run("cat /proc/loadavg 2>/dev/null")
        if load_res.success and load_res.stdout.strip():
            parts = load_res.stdout.strip().split()
            if len(parts) >= 3:
                try:
                    telemetry.load_1 = float(parts[0])
                    telemetry.load_5 = float(parts[1])
                    telemetry.load_15 = float(parts[2])
                except ValueError:
                    return

    def _collect_memory_swap(self, telemetry: TelemetryModel) -> None:
        mem_cmd = "awk '/MemTotal|MemAvailable|SwapTotal|SwapFree/ {print $1\" \"$2}' /proc/meminfo 2>/dev/null"
        mem_res = self.ssh.run(mem_cmd)
        if not mem_res.success:
            return

        data_kb: dict[str, int] = {}
        for line in mem_res.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) != 2:
                continue
            key = parts[0].rstrip(":")
            if parts[1].isdigit():
                data_kb[key] = int(parts[1])

        if "MemTotal" in data_kb:
            telemetry.mem_total_mb = data_kb["MemTotal"] // 1024
        if "MemAvailable" in data_kb:
            telemetry.mem_available_mb = data_kb["MemAvailable"] // 1024
        if "SwapTotal" in data_kb:
            telemetry.swap_total_mb = data_kb["SwapTotal"] // 1024
        if "SwapFree" in data_kb:
            telemetry.swap_free_mb = data_kb["SwapFree"] // 1024

    def _collect_disks(self, telemetry: TelemetryModel) -> None:
        inode_pct_by_mount: dict[str, float] = {}
        inode_total_by_mount: dict[str, int] = {}
        inode_res = self.ssh.run("df -P -i 2>/dev/null")
        if inode_res.success:
            for line in inode_res.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                mount = parts[-1]
                iused = parts[-4]
                ifree = parts[-3]
                iuse_pct = parts[-2].rstrip("%")
                if not (iused.isdigit() and ifree.isdigit() and iuse_pct.replace(".", "", 1).isdigit()):
                    continue
                inode_total_by_mount[mount] = int(iused) + int(ifree)
                inode_pct_by_mount[mount] = float(iuse_pct)

        df_res = self.ssh.run("df -P -k 2>/dev/null")
        if not df_res.success:
            return

        disks: list[DiskUsage] = []
        lines = df_res.stdout.splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue

            mount = parts[-1]
            if not mount.startswith("/"):
                continue

            total_kb = parts[-5]
            used_kb = parts[-4]
            use_pct = parts[-2].rstrip("%")

            if not (total_kb.isdigit() and used_kb.isdigit() and use_pct.isdigit()):
                continue

            total_gb = round(int(total_kb) / (1024 * 1024), 2)
            used_gb = round(int(used_kb) / (1024 * 1024), 2)
            used_percent = float(use_pct)

            disks.append(
                DiskUsage(
                    mount=mount,
                    total_gb=total_gb,
                    used_gb=used_gb,
                    used_percent=used_percent,
                    inode_total=inode_total_by_mount.get(mount),
                    inode_used_percent=inode_pct_by_mount.get(mount),
                )
            )

        telemetry.disks = sorted(disks, key=lambda d: d.used_percent, reverse=True)
