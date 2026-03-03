"""Continuous monitoring daemon for nginx-doctor.

Runs scheduled scans and sends alerts for new or resolved issues.
"""

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from nginx_doctor.config import ConfigManager
from nginx_doctor.connector.ssh import SSHConfig, SSHConnector
from nginx_doctor.integrations.notifier import NotificationManager

logger = logging.getLogger(__name__)


class MonitoringDaemon:
    """Daemon process for continuous server monitoring."""
    
    def __init__(
        self,
        config_mgr: ConfigManager | None = None,
        interval: int = 3600,
        servers: list[str] | None = None,
        pid_file: str = "/tmp/nginx-doctor.pid",
        log_file: str | None = None,
    ):
        self.config_mgr = config_mgr or ConfigManager()
        self.interval = interval
        self.servers = servers
        self.pid_file = pid_file
        self.log_file = log_file
        self.running = False
        self.notifier = NotificationManager(self.config_mgr)
        
        # State tracking per server
        self.previous_findings: dict[str, list[dict]] = {}
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure logging for daemon mode."""
        handlers = [logging.StreamHandler()]
        
        if self.log_file:
            handlers.append(logging.FileHandler(self.log_file))
        
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=handlers,
        )
    
    def start(self) -> None:
        """Start the daemon."""
        if self.is_running():
            logger.error("Daemon is already running")
            sys.exit(1)
        
        self._write_pid()
        self.running = True
        
        logger.info(f"Starting daemon with interval={self.interval}s")
        logger.info(f"Monitoring servers: {self.servers or 'all configured'}")
        
        # Setup signal handlers (Unix only)
        try:
            signal.signal(signal.SIGTERM, self._handle_signal)
            signal.signal(signal.SIGINT, self._handle_signal)
        except (AttributeError, ValueError):
            # Windows doesn't support SIGTERM
            pass
        
        try:
            self._run_loop()
        except Exception as e:
            logger.exception("Daemon loop error")
            raise
        finally:
            self._cleanup()
    
    def _run_loop(self) -> None:
        """Main daemon loop."""
        while self.running:
            start_time = time.time()
            
            try:
                self._run_scan_cycle()
            except Exception as e:
                logger.exception("Scan cycle failed")
            
            # Calculate sleep time
            elapsed = time.time() - start_time
            sleep_time = max(0, self.interval - elapsed)
            
            if self.running and sleep_time > 0:
                logger.debug(f"Sleeping for {sleep_time}s")
                time.sleep(sleep_time)
    
    def _run_scan_cycle(self) -> None:
        """Run one scan cycle for all monitored servers."""
        servers = self._get_servers_to_monitor()
        
        for server_name in servers:
            try:
                self._scan_server(server_name)
            except Exception as e:
                logger.error(f"Failed to scan {server_name}: {e}")
    
    def _get_servers_to_monitor(self) -> list[str]:
        """Get list of servers to monitor."""
        if self.servers:
            return self.servers
        
        # Get all configured profiles
        profiles = self.config_mgr.list_profiles()
        return list(profiles.keys())
    
    def _scan_server(self, server_name: str) -> None:
        """Scan a single server and process findings."""
        logger.info(f"Scanning {server_name}...")
        
        # Load server config
        cfg = self.config_mgr.load_profile(server_name)
        if not cfg:
            logger.warning(f"No config found for {server_name}")
            return
        
        # Run scan
        from nginx_doctor.cli import _run_full_scan
        
        try:
            with SSHConnector(cfg) as ssh:
                findings = _run_full_scan(ssh, cfg, timeout=300)
        except Exception as e:
            logger.error(f"Scan failed for {server_name}: {e}")
            return
        
        # Convert to comparable format
        current = self._serialize_findings(findings)
        previous = self.previous_findings.get(server_name, [])
        
        # Detect changes
        new_findings = self._detect_new_findings(current, previous)
        resolved_findings = self._detect_resolved_findings(current, previous)
        
        # Update state
        self.previous_findings[server_name] = current
        
        # Save state to disk
        self._save_state()
        
        # Notify about changes
        if new_findings or resolved_findings:
            logger.info(
                f"{server_name}: {len(new_findings)} new, {len(resolved_findings)} resolved"
            )
            self._notify_changes(server_name, new_findings, resolved_findings)
        else:
            logger.debug(f"{server_name}: No changes detected")
    
    def _serialize_findings(self, findings: list) -> list[dict]:
        """Serialize findings to comparable format."""
        return [
            {
                "id": f.id,
                "severity": f.severity.value,
                "condition": f.condition,
                "cause": f.cause,
            }
            for f in findings
        ]
    
    def _detect_new_findings(
        self, current: list[dict], previous: list[dict]
    ) -> list[dict]:
        """Find new findings that weren't in previous scan."""
        previous_ids = {self._finding_key(f) for f in previous}
        return [f for f in current if self._finding_key(f) not in previous_ids]
    
    def _detect_resolved_findings(
        self, current: list[dict], previous: list[dict]
    ) -> list[dict]:
        """Find resolved findings that were in previous but not current."""
        current_ids = {self._finding_key(f) for f in current}
        return [f for f in previous if self._finding_key(f) not in current_ids]
    
    def _finding_key(self, finding: dict) -> str:
        """Generate unique key for finding comparison."""
        return f"{finding['id']}:{finding['condition']}"
    
    def _notify_changes(
        self,
        server_name: str,
        new: list[dict],
        resolved: list[dict],
    ) -> None:
        """Send notifications about changes."""
        from nginx_doctor.model.finding import Finding, Severity
        from nginx_doctor.model.evidence import Evidence
        
        # Convert dicts back to Finding objects for notifier
        new_findings = []
        for f in new:
            try:
                severity = Severity(f["severity"])
            except ValueError:
                severity = Severity.INFO
            
            finding = Finding(
                id=f["id"],
                severity=severity,
                confidence=0.8,
                condition=f"[NEW] {f['condition']}",
                cause=f["cause"],
                evidence=[Evidence(source_file="daemon", line_number=1, excerpt="", command="")],
            )
            new_findings.append(finding)
        
        if new_findings:
            self.notifier.send_notification(
                new_findings,
                server_name=server_name,
                only_critical=False,
            )
    
    def _save_state(self) -> None:
        """Save daemon state to disk."""
        state = {
            "previous_findings": self.previous_findings,
            "last_update": datetime.utcnow().isoformat(),
        }
        
        state_file = Path(self.pid_file).parent / "nginx-doctor-state.json"
        state_file.write_text(json.dumps(state, indent=2))
    
    def _load_state(self) -> None:
        """Load daemon state from disk."""
        state_file = Path(self.pid_file).parent / "nginx-doctor-state.json"
        
        if state_file.exists():
            try:
                state = json.loads(state_file.read_text())
                self.previous_findings = state.get("previous_findings", {})
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
    
    def stop(self) -> None:
        """Stop the daemon."""
        logger.info("Stopping daemon...")
        self.running = False
        self._cleanup()
    
    def _cleanup(self) -> None:
        """Cleanup resources."""
        self._remove_pid()
        logger.info("Daemon stopped")
    
    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}")
        self.stop()
        sys.exit(0)
    
    def _write_pid(self) -> None:
        """Write PID file."""
        pid_path = Path(self.pid_file)
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text(str(os.getpid()))
    
    def _remove_pid(self) -> None:
        """Remove PID file."""
        try:
            Path(self.pid_file).unlink()
        except FileNotFoundError:
            pass
    
    def is_running(self) -> bool:
        """Check if daemon is running."""
        pid_file = Path(self.pid_file)
        
        if not pid_file.exists():
            return False
        
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)  # Check if process exists
            return True
        except (ValueError, OSError, ProcessLookupError):
            # Stale PID file
            self._remove_pid()
            return False
    
    def get_info(self) -> dict[str, Any]:
        """Get daemon information."""
        if not self.is_running():
            return {}
        
        pid = int(Path(self.pid_file).read_text().strip())
        
        return {
            "pid": pid,
            "started": "unknown",  # Could get from procfs on Linux
            "servers": self.servers or "all",
            "interval": self.interval,
        }
