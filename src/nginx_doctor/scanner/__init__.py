"""Scanner package - Data collection from remote servers.

Scanners run shell commands and collect raw data.
They do NOT analyze or reason - that's the analyzer's job.
"""

from nginx_doctor.scanner.filesystem import FilesystemScanner
from nginx_doctor.scanner.nginx import NginxScanner
from nginx_doctor.scanner.php import PHPScanner

__all__ = ["FilesystemScanner", "NginxScanner", "PHPScanner"]
