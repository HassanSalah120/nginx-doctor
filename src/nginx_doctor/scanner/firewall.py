"""Firewall Scanner - Detects local firewall presence and basic status.

This scanner identifies local firewall rules without claiming full network 
security (cloud/external firewalls are out of scope).
"""

from nginx_doctor.connector.ssh import SSHConnector


class FirewallScanner:
    """Scanner for local firewall status.

    Checks in order:
    1. ufw status
    2. nft list ruleset
    3. iptables -S
    """

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> str:
        """Perform firewall scan.

        Returns:
            String state: 'present', 'not_detected', or 'unknown'.
        """
        # 1. Check UFW
        if self.ssh.run("which ufw", timeout=2).success:
            res = self.ssh.run("ufw status", timeout=2)
            if res.success and "active" in res.stdout.lower() and "inactive" not in res.stdout.lower():
                return "present"

        # 2. Check NFT (Modern Ubuntu/Debian)
        if self.ssh.run("which nft", timeout=2).success:
            res = self.ssh.run("nft list ruleset", timeout=2)
            if res.success and len(res.stdout.strip()) > 100: # Heuristic for non-empty ruleset
                return "present"

        # 3. Check Iptables
        if self.ssh.run("which iptables", timeout=2).success:
            res = self.ssh.run("iptables -S", timeout=2)
            if res.success:
                # Common default rules like "-P INPUT ACCEPT" are usually not enough to count as "present"
                # If there are more than just policy lines, count as present
                lines = [l for l in res.stdout.strip().split("\n") if not l.startswith("-P ")]
                if len(lines) > 2:
                    return "present"

        # Fallback
        if not self.ssh.run("which ufw", timeout=2).success and \
           not self.ssh.run("which nft", timeout=2).success and \
           not self.ssh.run("which iptables", timeout=2).success:
            return "unknown"

        return "not_detected"
