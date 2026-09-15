import threading
from typing import Set

class Firewall:
    """
    Firewall — Manages the in-memory IP blocklist using a thread-safe set.
    """

    def __init__(self):
        self._blocked_ips: Set[str] = set()
        self._lock = threading.Lock()

    def block_ip(self, ip: str):
        with self._lock:
            if ip not in self._blocked_ips:
                self._blocked_ips.add(ip)
                print(f"[Firewall] BLOCKED IP: {ip}")

    def unblock_ip(self, ip: str):
        with self._lock:
            if ip in self._blocked_ips:
                self._blocked_ips.discard(ip)
                print(f"[Firewall] UNBLOCKED IP: {ip}")

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self) -> Set[str]:
        with self._lock:
            return set(self._blocked_ips)
