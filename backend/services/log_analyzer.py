from typing import List, Dict
from models.log_entry import LogEntry

class LogAnalyzer:
    """
    LogAnalyzer — Aggregates log entries by action type and IP address.
    """

    def count_action(self, logs: List[LogEntry], action: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for log in logs:
            if log.get_action() == action:
                ip = log.get_ip()
                counts[ip] = counts.get(ip, 0) + 1
        return counts

    def sort_by_ip(self, logs: List[LogEntry]) -> List[LogEntry]:
        logs.sort(key=lambda x: x.get_ip())
        return logs
