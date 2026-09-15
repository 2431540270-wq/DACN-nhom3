import os
import sys
import json
import re
import socketserver
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# Add current folder to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.log_entry import LogEntry
from core.security_bot import SecurityBot
from alert.alert_system import AlertSystem
from database.db import DatabaseConnection
from database.log_dao import LogDAO
from services.log_reader import LogReader
from services.realtime_monitor import RealTimeMonitor

# Shared global instances
bot = SecurityBot()
alert_system = AlertSystem()
log_dao = LogDAO()
reader = LogReader()

class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP Server handling requests concurrently."""
    daemon_threads = True

class ApiRequestHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Suppress standard HTTP request logging to keep console clean
        pass

    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()

    def _send_json(self, data, status_code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return {}
        raw_body = self.rfile.read(content_length).decode("utf-8")
        try:
            return json.loads(raw_body)
        except Exception:
            return {}

    def _get_client_ip(self) -> str:
        # Get remote IP address
        client_ip = self.client_address[0]
        # X-Forwarded-For header support if behind proxy
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        return client_ip

    def do_GET(self):
        url_path = self.path.split("?")[0]

        # ENDPOINT 1: GET /api/analyze
        if url_path == "/api/analyze":
            try:
                if DatabaseConnection.is_available():
                    logs = log_dao.get_all_logs()
                    print(f"[API /analyze] Source: DATABASE — {len(logs)} row(s)")
                else:
                    logs = reader.read_log("logs/network.log")
                    print(f"[API /analyze] Source: FILE — {len(logs)} row(s)")

                display_total = len(logs)
                if DatabaseConnection.is_available():
                    db_count = log_dao.get_log_count()
                    if db_count > display_total:
                        display_total = db_count

                risk_avg = 0.0
                if logs:
                    total_risk = sum(l.get_score() for l in logs)
                    risk_avg = round(total_risk / len(logs), 1)

                resp = {
                    "status": "analyzed",
                    "totalLogs": display_total,
                    "riskAvg": risk_avg
                }
                print(f"[API /analyze] Response: {resp}")
                self._send_json(resp)
            except Exception as e:
                print(f"[API /analyze] ERROR: {e}")
                self._send_json({"error": str(e)}, 500)

        # ENDPOINT 2: GET /api/logs
        elif url_path == "/api/logs":
            try:
                logs_to_send = []
                if DatabaseConnection.is_available():
                    db_logs = log_dao.get_all_logs()
                    if db_logs:
                        logs_to_send = db_logs
                if not logs_to_send:
                    logs_to_send = reader.read_log("logs/network.log")

                limit_logs = logs_to_send[:100]
                resp = [
                    {
                        "time": l.get_time(),
                        "ip": l.get_ip(),
                        "action": l.get_action(),
                        "attack": l.get_attack_type(),
                        "score": l.get_score(),
                        "status": l.get_status()
                    }
                    for l in limit_logs
                ]
                print(f"[API /logs] Returning {len(resp)} row(s)")
                self._send_json(resp)
            except Exception as e:
                print(f"[API /logs] ERROR: {e}")
                self._send_json({"error": str(e)}, 500)

        # ENDPOINT 3: GET /api/alerts
        elif url_path == "/api/alerts":
            try:
                resp = []
                if DatabaseConnection.is_available():
                    db_alerts = log_dao.get_alerts_from_db()
                    print(f"[API /alerts] {len(db_alerts)} alert(s) from DB")
                    resp = db_alerts
                else:
                    raw_alerts = alert_system.get_alerts()
                    print(f"[API /alerts] {len(raw_alerts)} alert(s) from memory (DB unavailable)")
                    for alert in raw_alerts:
                        level = "LOW"
                        score = 10
                        if "🚨" in alert:
                            level = "CRITICAL"
                            score = 90
                        elif "🔴" in alert:
                            level = "HIGH"
                            score = 70
                        elif "⚠" in alert:
                            level = "MEDIUM"
                            score = 50

                        if "BRUTE_FORCE" in alert:
                            attack = "BRUTE_FORCE"
                        elif "REQUEST_FLOOD" in alert:
                            attack = "REQUEST_FLOOD"
                        elif level == "CRITICAL":
                            attack = "BRUTE_FORCE"
                        elif level == "HIGH":
                            attack = "REQUEST_FLOOD"
                        else:
                            attack = "DANGEROUS_ACTIVITY"

                        ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", alert)
                        ip_str = ip_match.group(0) if ip_match else "0.0.0.0"

                        time_str = ""
                        if "[" in alert and "]" in alert:
                            time_str = alert[alert.find("[")+1 : alert.find("]")]

                        resp.append({
                            "time": time_str,
                            "level": level,
                            "attack": attack,
                            "ip": ip_str,
                            "score": score
                        })

                self._send_json(resp)
            except Exception as e:
                print(f"[API /alerts] ERROR: {e}")
                self._send_json({"error": str(e)}, 500)

        # ENDPOINT 4: GET /api/blocked
        elif url_path == "/api/blocked":
            try:
                blocked_ips = list(bot.get_firewall().get_blocked_ips())
                print(f"[API /blocked] {len(blocked_ips)} blocked IP(s)")
                self._send_json(blocked_ips)
            except Exception as e:
                print(f"[API /blocked] ERROR: {e}")
                self._send_json({"error": str(e)}, 500)

        # ENDPOINT 9: GET /api/check-block
        elif url_path == "/api/check-block":
            try:
                caller_ip = self._get_client_ip()
                is_blocked = bot.get_firewall().is_blocked(caller_ip)
                print(f"[API /check-block] IP: {caller_ip} blocked={is_blocked}")
                self._send_json({"blocked": is_blocked, "ip": caller_ip})
            except Exception as e:
                print(f"[API /check-block] ERROR: {e}")
                self._send_json({"error": str(e)}, 500)

        else:
            self._send_json({"error": "Endpoint not found"}, 404)

    def do_POST(self):
        url_path = self.path.split("?")[0]

        # ENDPOINT 5: POST /api/block
        if url_path == "/api/block":
            try:
                body = self._read_json_body()
                ip = body.get("ip")
                if not ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    self._send_json({"success": False, "message": "Invalid IP address"}, 400)
                    return

                bot.get_firewall().block_ip(ip)
                print(f"[API /block] Manually blocked IP: {ip}")
                self._send_json({"success": True, "message": f"Blocked IP {ip}"})
            except Exception as e:
                print(f"[API /block] ERROR: {e}")
                self._send_json({"error": str(e)}, 500)

        # ENDPOINT 6: POST /api/unblock
        elif url_path == "/api/unblock":
            try:
                body = self._read_json_body()
                ip = body.get("ip")
                if not ip:
                    self._send_json({"success": False, "message": "Invalid IP address"}, 400)
                    return

                bot.clear_history(ip)
                bot.get_firewall().unblock_ip(ip)

                if DatabaseConnection.is_available():
                    log_dao.unblock_in_db(ip)

                print(f"[API /unblock] Unblocked IP: {ip}")
                self._send_json({"success": True, "message": f"Unblocked IP {ip}"})
            except Exception as e:
                print(f"[API /unblock] ERROR: {e}")
                self._send_json({"error": str(e)}, 500)

        # ENDPOINT 7: POST /api/attack/bruteforce
        elif url_path == "/api/attack/bruteforce":
            try:
                attacker_ip = self._get_client_ip()
                if bot.get_firewall().is_blocked(attacker_ip):
                    print(f"[API /attack/bruteforce] BLOCKED IP tried: {attacker_ip}")
                    self._send_json({"blocked": True, "message": "Your IP is blocked"}, 403)
                    return

                if DatabaseConnection.is_available():
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    attack_log = LogEntry(now_str, attacker_ip, "LOGIN_FAIL")
                    attack_log.set_status("SUSPICIOUS")
                    attack_log.set_attack_type("BRUTE_FORCE")
                    log_dao.insert_log(attack_log)

                print(f"[API /attack/bruteforce] LOGIN_FAIL from: {attacker_ip}")
                self._send_json({"success": True, "action": "LOGIN_FAIL", "ip": attacker_ip})
            except Exception as e:
                print(f"[API /attack/bruteforce] ERROR: {e}")
                self._send_json({"error": str(e)}, 500)

        # ENDPOINT 8: POST /api/attack/flood
        elif url_path == "/api/attack/flood":
            try:
                attacker_ip = self._get_client_ip()
                if bot.get_firewall().is_blocked(attacker_ip):
                    print(f"[API /attack/flood] BLOCKED IP tried: {attacker_ip}")
                    self._send_json({"blocked": True, "message": "Your IP is blocked"}, 403)
                    return

                if DatabaseConnection.is_available():
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    attack_log = LogEntry(now_str, attacker_ip, "REQUEST")
                    attack_log.set_status("PASS")
                    attack_log.set_attack_type("REQUEST_FLOOD")
                    log_dao.insert_log(attack_log)

                print(f"[API /attack/flood] REQUEST from: {attacker_ip}")
                self._send_json({"success": True, "action": "REQUEST", "ip": attacker_ip})
            except Exception as e:
                print(f"[API /attack/flood] ERROR: {e}")
                self._send_json({"error": str(e)}, 500)

        else:
            self._send_json({"error": "Endpoint not found"}, 404)

def main():
    print("============================================")
    print("   AI Security IDS (Python) - Starting up")
    print("============================================")

    print("\n[Step 1] Testing MySQL connection...")
    db_ok = DatabaseConnection.test_connection()
    if not db_ok:
        print("   MySQL unavailable -> Using text file as data source")

    print("\n[Step 2] Initializing SecurityBot + AlertSystem...")
    if db_ok:
        blocked_ips = log_dao.get_blocked_ips()
        for ip in blocked_ips:
            bot.get_firewall().block_ip(ip)

    print("   SecurityBot + AlertSystem ready")

    print("\n[Step 3] Starting RealTimeMonitor...")
    monitor = RealTimeMonitor(bot, alert_system)
    monitor.start()
    print("   RealTimeMonitor started (scan interval: 2s)")

    print("\n[Step 4] Starting API Server...")
    port = 8080
    server_address = ("0.0.0.0", port)
    httpd = ThreadingHTTPServer(server_address, ApiRequestHandler)

    print("\n============================================")
    print("   SYSTEM READY (Python Backend)")
    print(f"   API:      http://localhost:{port}")
    print(f"   Database: {'MySQL (connected)' if db_ok else 'File text (fallback)'}")
    print("   Blue FE:  Open frontend/dashboard.html")
    print("   Red FE:   Open frontend/redteam FE/reddash.html")
    print("   Logs are generated by Red Team attack actions")
    print("============================================\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping API server...")
        monitor.stop()
        httpd.server_close()

if __name__ == "__main__":
    main()
