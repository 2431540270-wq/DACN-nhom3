import threading
from typing import List, Dict, Set
from models.log_entry import LogEntry
from core.firewall import Firewall
from alert.alert_system import AlertSystem
from services.log_analyzer import LogAnalyzer
from core.ai_detector import AIDetector

class SecurityBot:
    """
    SecurityBot — Evaluates log entries, calculates risk scores,
    manages danger history, triggers alerts, and interacts with the Firewall.
    Tích hợp AIDetector để nhận diện thông minh các cuộc tấn công Web và luồng mạng.
    """

    def __init__(self):
        self.danger_history: Dict[str, int] = {}
        self.last_fail_count: Dict[str, int] = {}
        self.last_request_count: Dict[str, int] = {}
        self.last_alert_score: Dict[str, int] = {}
        self.firewall = Firewall()
        self.ai_detector = AIDetector()
        self._lock = threading.Lock()

    def analyze(self, logs: List[LogEntry], alert_system: AlertSystem):
        with self._lock:
            analyzer = LogAnalyzer()

            fail_map = analyzer.count_action(logs, "LOGIN_FAIL")
            request_map = analyzer.count_action(logs, "REQUEST")
            success_map = analyzer.count_action(logs, "LOGIN_SUCCESS")

            all_ips: Set[str] = set()
            all_ips.update(fail_map.keys())
            all_ips.update(request_map.keys())
            all_ips.update(success_map.keys())

            existing_ips = set(self.last_fail_count.keys())
            for old_ip in existing_ips:
                if old_ip not in all_ips:
                    self.last_fail_count[old_ip] = self.last_fail_count.get(old_ip, 0)
                    self.last_request_count[old_ip] = self.last_request_count.get(old_ip, 0)

            for ip in all_ips:
                if self.firewall.is_blocked(ip):
                    for log in logs:
                        if log.get_ip() == ip:
                            log.set_score(90)
                            log.set_status("BLOCKED")
                            if not log.get_attack_type() or log.get_attack_type() == "NORMAL":
                                log.set_attack_type("BLOCKED")
                    continue

                fail = fail_map.get(ip, 0)
                request = request_map.get(ip, 0)
                success = success_map.get(ip, 0)
                history = self.danger_history.get(ip, 0)

                prev_fail = self.last_fail_count.get(ip, 0)
                prev_request = self.last_request_count.get(ip, 0)
                has_new_activity = (fail > prev_fail) or (request > prev_request)

                self.last_fail_count[ip] = fail
                self.last_request_count[ip] = request

                # ── Phân tích thông minh bằng AI Detector ──
                ai_attack_type = None
                ai_max_risk = 0
                for log in logs:
                    if log.get_ip() == ip:
                        desc = log.get_description()
                        if desc and desc.strip():
                            ai_res = self.ai_detector.predict_payload(desc)
                            if ai_res.get("is_attack"):
                                ai_attack_type = f"WEB_{ai_res['attack_type'].upper()}"
                                ai_max_risk = max(ai_max_risk, ai_res.get("risk_score", 0))
                                log.set_attack_type(ai_attack_type)
                                log.set_score(max(log.get_score(), ai_res.get("risk_score", 0)))

                risk_score = (fail * 10) + (request * 5) - (success * 1) + (history * 5)
                risk_score = max(risk_score, ai_max_risk, 0)

                attack_type = "NORMAL"
                if ai_attack_type:
                    attack_type = ai_attack_type
                elif fail >= 5:
                    attack_type = "BRUTE_FORCE"
                elif request >= 20:
                    attack_type = "REQUEST_FLOOD"

                status = "PASS"
                prev_alert_score = self.last_alert_score.get(ip, 0)

                if risk_score >= 15 and (has_new_activity or ai_attack_type):
                    level = min(history + 1, 10)
                    self.danger_history[ip] = level

                    if risk_score >= 45:
                        self.firewall.block_ip(ip)
                        status = "BLOCKED"
                    elif risk_score >= 30:
                        status = "MONITORING"
                    else:
                        status = "SUSPICIOUS"

                    if risk_score > prev_alert_score:
                        alert_system.add_alert(ip, attack_type, risk_score, status)
                        self.last_alert_score[ip] = risk_score

                self._update_logs_for_ip(logs, ip, risk_score, status, attack_type)

    def _update_logs_for_ip(self, logs: List[LogEntry], ip: str,
                            risk_score: int, status: str, attack_type: str):
        for log in logs:
            if log.get_ip() == ip:
                current_score = max(log.get_score(), risk_score)
                current_status = log.get_status()

                if status == "PASS" and current_status in ("SUSPICIOUS", "MONITORING"):
                    pass
                else:
                    log.set_status(status)

                log.set_score(current_score)

    def clear_history(self, ip: str):
        with self._lock:
            self.danger_history.pop(ip, None)
            self.last_fail_count.pop(ip, None)
            self.last_request_count.pop(ip, None)
            self.last_alert_score.pop(ip, None)
            print(f"[SecurityBot] Cleared danger history for IP: {ip}")

    def get_firewall(self) -> Firewall:
        return self.firewall

    def get_ai_detector(self) -> AIDetector:
        return self.ai_detector
