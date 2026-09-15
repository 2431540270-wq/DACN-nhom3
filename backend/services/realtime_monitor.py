import time
import threading
from typing import List
from models.log_entry import LogEntry
from core.security_bot import SecurityBot
from alert.alert_system import AlertSystem
from database.db import DatabaseConnection
from database.log_dao import LogDAO
from services.log_reader import LogReader

class RealTimeMonitor(threading.Thread):
    """
    RealTimeMonitor — Background daemon thread that periodically scans logs,
    runs SecurityBot analysis, and updates database records.
    """

    SCAN_INTERVAL_SEC = 2.0

    def __init__(self, bot: SecurityBot, alert_system: AlertSystem):
        super().__init__(name="RealTimeMonitor-Thread", daemon=True)
        self.bot = bot
        self.alert_system = alert_system
        self.log_dao = LogDAO()
        self.reader = LogReader()
        self.running = True

    def run(self):
        print("[RealTimeMonitor] Started. Scanning logs every 2s...")

        while self.running:
            try:
                if DatabaseConnection.is_available():
                    logs = self.log_dao.get_all_logs()
                    print(f"[Monitor] Read {len(logs)} log(s) from DATABASE")
                else:
                    logs = self.reader.read_log("logs/network.log")
                    print(f"[Monitor] Read {len(logs)} log(s) from FILE")

                if logs:
                    self.bot.analyze(logs, self.alert_system)

                    if DatabaseConnection.is_available():
                        self.log_dao.update_logs(logs)

                    recent = logs[-5:] if len(logs) >= 5 else logs
                    print("--- Last 5 Log Entries ---")
                    for l in recent:
                        print(f"{l.get_time()} | IP: {l.get_ip()} | Attack: {l.get_attack_type()} | Risk: {l.get_score()}")
                else:
                    print("[Monitor] No logs available yet.")

            except Exception as e:
                print(f"[RealTimeMonitor] Error in scan loop: {e}")

            time.sleep(self.SCAN_INTERVAL_SEC)

    def stop(self):
        self.running = False
