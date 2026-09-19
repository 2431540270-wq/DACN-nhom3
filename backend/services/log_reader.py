import os
from typing import List
from models.log_entry import LogEntry

class LogReader:
    """
    LogReader — Reads a plain-text network log file line by line
    and parses each line into a LogEntry object.
    """

    def read_log(self, file_name: str) -> List[LogEntry]:
        logs: List[LogEntry] = []
        if not os.path.exists(file_name):
            print(f"[LogReader] File not found: {file_name} — skipping file read.")
            return logs

        try:
            with open(file_name, "r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str:
                        continue

                    parts = line_str.split()
                    if len(parts) < 2:
                        print(f"[LogReader] Skipping malformed line: {line_str}")
                        continue

                    time_val = parts[0]
                    ip_val = parts[1]
                    action_val = parts[2] if len(parts) > 2 else "REQUEST"

                    entry = LogEntry(time_val, ip_val, action_val)
                    if len(parts) > 3:
                        entry.set_description(" ".join(parts[3:]))
                    logs.append(entry)
        except Exception as e:
            print(f"[LogReader] Error reading file {file_name}: {e}")

        return logs
