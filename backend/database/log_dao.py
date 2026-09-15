from typing import List, Dict, Any
from models.log_entry import LogEntry
from database.db import DatabaseConnection

class LogDAO:
    """
    LogDAO — Data Access Object for the 'logs' and 'alerts' tables in MySQL.
    """

    def insert_log(self, log: LogEntry) -> bool:
        sql = ("INSERT INTO logs (timestamp, ip_address, action, status, attack_type, score, description) "
               "VALUES (%s, %s, %s, %s, %s, %s, %s)")
        conn = DatabaseConnection.get_connection()
        if not conn:
            return False

        try:
            cursor = conn.cursor()
            desc = f"{log.get_action()} from IP {log.get_ip()}"
            cursor.execute(sql, (
                log.get_time(), log.get_ip(), log.get_action(),
                log.get_status(), log.get_attack_type(), log.get_score(), desc
            ))
            conn.commit()
            cursor.close()
            conn.close()
            print(f"[DB] Saved log: {log.get_ip()} {log.get_action()}")
            return True
        except Exception as e:
            print(f"[DB] INSERT error: {e}")
            return False

    def insert_logs(self, logs: List[LogEntry]) -> int:
        if not logs:
            return 0
        sql = ("INSERT INTO logs (timestamp, ip_address, action, status, attack_type, score, description) "
               "VALUES (%s, %s, %s, %s, %s, %s, %s)")
        conn = DatabaseConnection.get_connection()
        if not conn:
            return 0

        count = 0
        try:
            cursor = conn.cursor()
            data = [
                (l.get_time(), l.get_ip(), l.get_action(),
                 l.get_status(), l.get_attack_type(), l.get_score(),
                 f"{l.get_action()} from IP {l.get_ip()}")
                for l in logs
            ]
            cursor.executemany(sql, data)
            conn.commit()
            count = cursor.rowcount if cursor.rowcount > 0 else len(data)
            cursor.close()
            conn.close()
            print(f"[DB] Batch insert: {count}/{len(logs)} rows")
        except Exception as e:
            print(f"[DB] Batch INSERT error: {e}")

        return count

    def get_all_logs(self) -> List[LogEntry]:
        logs: List[LogEntry] = []
        sql = ("SELECT id, timestamp, ip_address, action, status, attack_type, score, description "
               "FROM logs ORDER BY timestamp DESC LIMIT 100")
        conn = DatabaseConnection.get_connection()
        if not conn:
            return logs

        try:
            cursor = conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            for row in rows:
                entry = self._map_result_to_log_entry(row)
                logs.append(entry)
            cursor.close()
            conn.close()
            print(f"[DB] Loaded {len(logs)} log row(s) from database")
        except Exception as e:
            print(f"[DB] SELECT error: {e}")

        return logs

    def get_logs_by_ip(self, ip: str) -> List[LogEntry]:
        logs: List[LogEntry] = []
        sql = ("SELECT id, timestamp, ip_address, action, status, attack_type, score, description "
               "FROM logs WHERE ip_address = %s ORDER BY timestamp DESC")
        conn = DatabaseConnection.get_connection()
        if not conn:
            return logs

        try:
            cursor = conn.cursor()
            cursor.execute(sql, (ip,))
            rows = cursor.fetchall()
            for row in rows:
                entry = self._map_result_to_log_entry(row)
                logs.append(entry)
            cursor.close()
            conn.close()
            print(f"[DB] Found {len(logs)} log(s) for IP: {ip}")
        except Exception as e:
            print(f"[DB] SELECT by IP error: {e}")

        return logs

    def get_log_count(self) -> int:
        sql = "SELECT COUNT(*) FROM logs"
        conn = DatabaseConnection.get_connection()
        if not conn:
            return 0

        try:
            cursor = conn.cursor()
            cursor.execute(sql)
            res = cursor.fetchone()
            cursor.close()
            conn.close()
            return res[0] if res else 0
        except Exception as e:
            print(f"[DB] COUNT error: {e}")
            return 0

    def update_logs(self, logs: List[LogEntry]) -> int:
        sql = "UPDATE logs SET attack_type = %s, status = %s, score = %s WHERE id = %s AND id > 0"
        conn = DatabaseConnection.get_connection()
        if not conn:
            return 0

        to_update = [l for l in logs if l.get_id() > 0 and l.is_modified_flag()]
        if not to_update:
            return 0

        count = 0
        try:
            cursor = conn.cursor()
            data = [
                (l.get_attack_type(), l.get_status(), l.get_score(), l.get_id())
                for l in to_update
            ]
            cursor.executemany(sql, data)
            conn.commit()
            count = cursor.rowcount if cursor.rowcount > 0 else len(data)
            cursor.close()
            conn.close()
            print(f"[DB] updateLogs: updated {count} row(s)")
        except Exception as e:
            print(f"[DB] updateLogs error: {e}")

        return count

    def get_blocked_ips(self) -> List[str]:
        blocked: List[str] = []
        sql = "SELECT DISTINCT ip_address FROM logs WHERE status = 'BLOCKED'"
        conn = DatabaseConnection.get_connection()
        if not conn:
            return blocked

        try:
            cursor = conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            for r in rows:
                blocked.append(r[0])
            cursor.close()
            conn.close()
            if blocked:
                print(f"[DB] Loaded {len(blocked)} BLOCKED IP(s) from database into Firewall")
        except Exception as e:
            print(f"[DB] getBlockedIPs error: {e}")

        return blocked

    def unblock_in_db(self, ip: str) -> int:
        total = 0
        conn = DatabaseConnection.get_connection()
        if not conn:
            return 0

        try:
            cursor = conn.cursor()
            delete_logs_sql = "DELETE FROM logs WHERE ip_address = %s"
            cursor.execute(delete_logs_sql, (ip,))
            deleted_logs = cursor.rowcount
            print(f"[DB] unblockInDB: Deleted {deleted_logs} log(s) for IP: {ip}")
            total += deleted_logs

            delete_alerts_sql = "DELETE FROM alerts WHERE ip_address = %s"
            cursor.execute(delete_alerts_sql, (ip,))
            deleted_alerts = cursor.rowcount
            print(f"[DB] unblockInDB: Deleted {deleted_alerts} alert(s) for IP: {ip}")
            total += deleted_alerts

            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"[DB] unblockInDB error: {e}")

        return total

    def get_alerts_from_db(self) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        sql = ("SELECT ip_address, attack_type, risk_score, alert_level, created_at "
               "FROM alerts ORDER BY created_at DESC LIMIT 200")
        conn = DatabaseConnection.get_connection()
        if not conn:
            return result

        try:
            cursor = conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            for r in rows:
                result.append({
                    "ip": r[0],
                    "attack": r[1],
                    "score": r[2],
                    "level": r[3],
                    "time": str(r[4])
                })
            cursor.close()
            conn.close()
            print(f"[DB] getAlertsFromDB: Loaded {len(result)} alert(s)")
        except Exception as e:
            print(f"[DB] getAlertsFromDB error: {e}")

        return result

    def _map_result_to_log_entry(self, row) -> LogEntry:
        # row: (id, timestamp, ip_address, action, status, attack_type, score, description)
        id_val = row[0]
        time_val = str(row[1]) if row[1] is not None else ""
        ip_val = str(row[2]) if row[2] is not None else ""
        action_val = str(row[3]) if row[3] is not None else ""
        status_val = str(row[4]) if row[4] is not None else "PASS"
        attack_val = str(row[5]) if row[5] is not None else "NORMAL"
        db_score = row[6] if row[6] is not None else 0
        desc_val = str(row[7]) if row[7] is not None else None

        entry = LogEntry(time_val, ip_val, action_val, id_val=id_val)
        entry.set_attack_type(attack_val if attack_val else "NORMAL")
        entry.set_status(status_val)

        score_to_use = db_score if db_score > 0 else self._calculate_score_from_status(status_val)
        entry.set_score(score_to_use)
        entry.set_description(desc_val)
        entry.reset_modified()
        return entry

    def _calculate_score_from_status(self, status: str) -> int:
        if status == "BLOCKED":
            return 90
        elif status == "MONITORING":
            return 60
        elif status == "SUSPICIOUS":
            return 30
        elif status == "PASS":
            return 5
        return 0
