import threading
from datetime import datetime
from typing import List

class AlertSystem:
    """
    AlertSystem — Stores security alerts in database and maintains an in-memory fallback list.
    """

    def __init__(self):
        self._alerts: List[str] = []
        self._lock = threading.Lock()

    def _save_alert_to_database(self, ip: str, attack_type: str, risk_score: int,
                                alert_level: str, message: str):
        try:
            from database.db import DatabaseConnection
            if DatabaseConnection.is_available():
                conn = DatabaseConnection.get_connection()
                if conn:
                    cursor = conn.cursor()
                    sql = ("INSERT INTO alerts (ip_address, attack_type, risk_score, alert_level, message) "
                           "VALUES (%s, %s, %s, %s, %s)")
                    cursor.execute(sql, (ip, attack_type, risk_score, alert_level, message))
                    conn.commit()
                    cursor.close()
                    conn.close()
        except Exception as e:
            print(f"[AlertSystem] DB insert failed: {e}")

    def add_alert(self, ip: str, attack_type: str, risk_score: int, status: str):
        if risk_score >= 45:
            alert_level = "CRITICAL"
            message = f"🚨 CRITICAL {attack_type} IP {ip} | Risk Score: {risk_score} | IP BLOCKED"
        elif risk_score >= 30:
            alert_level = "HIGH"
            message = f"🔴 HIGH RISK {attack_type} IP {ip} | Risk Score: {risk_score}"
        else:
            alert_level = "MEDIUM"
            message = f"⚠ Suspicious {attack_type} IP {ip} | Risk Score: {risk_score}"

        timestamp = datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
        timestamped_message = f"[{timestamp}] {message}"

        with self._lock:
            if len(self._alerts) >= 500:
                self._alerts = self._alerts[50:]
            self._alerts.append(timestamped_message)

        self._save_alert_to_database(ip, attack_type, risk_score, alert_level, timestamped_message)
        print(timestamped_message)

    def get_alerts(self) -> List[str]:
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self):
        with self._lock:
            self._alerts.clear()
