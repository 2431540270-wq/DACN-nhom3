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

                    tokens = line_str.split()
                    if len(tokens) < 2:
                        print(f"[LogReader] Skipping malformed line: {line_str}")
                        continue

                    # Kiểm tra xem tokens[0] và tokens[1] có phải là ngày và giờ (YYYY-MM-DD HH:MM:SS)
                    if len(tokens) >= 3 and "-" in tokens[0] and ":" in tokens[1]:
                        time_val = f"{tokens[0]} {tokens[1]}"
                        ip_val = tokens[2]
                        action_val = tokens[3] if len(tokens) > 3 else "REQUEST"
                        desc = " ".join(tokens[4:]) if len(tokens) > 4 else None
                    else:
                        time_val = tokens[0]
                        ip_val = tokens[1]
                        action_val = tokens[2] if len(tokens) > 2 else "REQUEST"
                        desc = " ".join(tokens[3:]) if len(tokens) > 3 else None

                    entry = LogEntry(time_val, ip_val, action_val)
                    if desc:
                        entry.set_description(desc)
                    logs.append(entry)
        except Exception as e:
            print(f"[LogReader] Error reading file {file_name}: {e}")

        return logs
