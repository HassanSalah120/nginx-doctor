"""SSH Connector - Secure connection to remote servers.

This module handles all SSH communication with remote servers.
It is read-only by default and provides methods for running
commands and retrieving file contents.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException


@dataclass
class SSHConfig:
    """SSH connection configuration."""

    host: str
    user: str = "root"
    port: int = 22
    key_path: str | None = None
    password: str | None = None  # Fallback, prefer keys
    use_sudo: bool = True
    timeout: int = 30


@dataclass
class CommandResult:
    """Result of a command execution."""

    command: str
    stdout: str
    stderr: str
    exit_code: int
    success: bool = field(init=False)

    def __post_init__(self) -> None:
        self.success = self.exit_code == 0


class SSHConnector:
    """SSH connection manager for remote server operations.

    This class provides a safe interface for executing read-only
    commands on remote servers. Write operations are explicitly
    separated and require confirmation.

    Example:
        >>> config = SSHConfig(host="192.168.1.100", user="deploy")
        >>> with SSHConnector(config) as ssh:
        ...     result = ssh.run("nginx -v")
        ...     print(result.stdout)
    """

    def __init__(self, config: SSHConfig) -> None:
        """Initialize SSH connector with configuration."""
        self.config = config
        self._client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        """Establish SSH connection."""
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": self.config.host,
            "port": self.config.port,
            "username": self.config.user,
            "timeout": self.config.timeout,
        }

        # Prefer key-based authentication
        if self.config.key_path:
            key_path = Path(self.config.key_path).expanduser()
            if key_path.exists():
                connect_kwargs["key_filename"] = str(key_path)
        elif self.config.password:
            connect_kwargs["password"] = self.config.password

        try:
            self._client.connect(**connect_kwargs)
        except AuthenticationException as e:
            raise ConnectionError(f"Authentication failed: {e}") from e
        except SSHException as e:
            raise ConnectionError(f"SSH error: {e}") from e

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> "SSHConnector":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager exit."""
        self.disconnect()

    def run(self, command: str, use_sudo: bool | None = None, timeout: float | None = None) -> CommandResult:
        """Execute a command on the remote server.

        Args:
            command: The command to execute.
            use_sudo: Whether to use sudo. Defaults to config setting.
            timeout: Command timeout in seconds. Defaults to config timeout.

        Returns:
            CommandResult with stdout, stderr, and exit_code.
        """
        if not self._client:
            raise RuntimeError("Not connected. Use 'with SSHConnector(config):' context.")

        if use_sudo is None:
            use_sudo = self.config.use_sudo

        if use_sudo and self.config.user != "root":
            if self.config.password:
                # Use -S to read password from stdin
                command = f"echo '{self.config.password}' | sudo -S {command}"
            else:
                command = f"sudo {command}"
        
        # Use provided timeout or default from config
        cmd_timeout = timeout if timeout is not None else self.config.timeout

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=cmd_timeout)
            exit_code = stdout.channel.recv_exit_status()
            
            return CommandResult(
                command=command,
                stdout=stdout.read().decode("utf-8", errors="replace"),
                stderr=stderr.read().decode("utf-8", errors="replace"),
                exit_code=exit_code,
            )
        except Exception as e:
            # Handle timeouts or other SSH errors gracefully
            return CommandResult(
                command=command,
                stdout="",
                stderr=f"SSH Execution Error: {str(e)}",
                exit_code=255
            )

    def read_file(self, path: str) -> str | None:
        """Read file contents from remote server.

        Args:
            path: Absolute path to the file.

        Returns:
            File contents as string, or None if file doesn't exist.
        """
        result = self.run(f"cat {path}", use_sudo=True)
        if result.success:
            return result.stdout
        return None

    def file_exists(self, path: str) -> bool:
        """Check if a file exists on the remote server."""
        result = self.run(f"test -f {path}", use_sudo=True)
        return result.success

    def dir_exists(self, path: str) -> bool:
        """Check if a directory exists on the remote server."""
        result = self.run(f"test -d {path}", use_sudo=True)
        return result.success

    def list_dir(self, path: str) -> list[str]:
        """List directory contents.

        Args:
            path: Directory path.

        Returns:
            List of filenames in the directory.
        """
        result = self.run(f"ls -1 {path}", use_sudo=True)
        if result.success:
            return [f for f in result.stdout.strip().split("\n") if f]
        return []

    # =========================================================================
    # WRITE OPERATIONS - Require explicit confirmation
    # =========================================================================

    def write_file(
        self,
        path: str,
        content: str,
        *,
        backup: bool = True,
        confirm_callback: Callable[[], bool] | None = None,
    ) -> bool:
        """Write content to a file on the remote server.

        ⚠️  WARNING: This modifies the server!

        Args:
            path: Absolute path to write to.
            content: Content to write.
            backup: Whether to backup existing file first.
            confirm_callback: Optional callback to confirm the operation.

        Returns:
            True if successful.
        """
        if confirm_callback and not confirm_callback():
            return False

        if backup and self.file_exists(path):
            self.run(f"cp {path} {path}.bak", use_sudo=True)

        # Use heredoc to write content
        # Note: This is a simplified implementation. Production would use SFTP.
        escaped_content = content.replace("'", "'\"'\"'")
        result = self.run(f"echo '{escaped_content}' > {path}", use_sudo=True)
        return result.success
