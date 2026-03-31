package core;

import java.util.*;
import model.LogEntry;
import alert.AlertSystem;
import service.LogAnalyzer;

public class SecurityBot {

    private Map<String, Integer> dangerHistory = new HashMap<>();

    /**
     * Firewall instance — blocks IPs that exceed the risk threshold.
     */
    private Firewall firewall = new Firewall();

    /**
     * Analyzes a list of log entries and assigns risk scores, statuses,
     * and attack types to each entry based on IP behavior.
     *
     * @param logs        List of network log events (LogEntry).
     * @param alertSystem AlertSystem used to emit alert messages.
     */
    public void analyze(List<LogEntry> logs, AlertSystem alertSystem) {

        LogAnalyzer analyzer = new LogAnalyzer();

        // Step 1: Count actions per IP
        Map<String, Integer> failMap = analyzer.countAction(logs, "LOGIN_FAIL");
        Map<String, Integer> requestMap = analyzer.countAction(logs, "REQUEST");
        Map<String, Integer> successMap = analyzer.countAction(logs, "LOGIN_SUCCESS");

        // Step 2: Collect all unique IPs seen across all action maps
        Set<String> allIPs = new HashSet<>();
        allIPs.addAll(failMap.keySet());
        allIPs.addAll(requestMap.keySet());
        allIPs.addAll(successMap.keySet());

        // Step 3: Evaluate each IP
        for (String ip : allIPs) {

            if (firewall.isBlocked(ip)) {
                for (LogEntry log : logs) {
                    if (log.getIp().equals(ip)) {
                        log.setScore(90);
                        log.setStatus("BLOCKED");
                        // Giữ nguyên attackType đã có từ CSDL, chỉ đổi nếu nó đang là NORMAL.
                        if (log.getAttackType() == null || log.getAttackType().equals("NORMAL")) {
                            log.setAttackType("BLOCKED");
                        }
                    }
                }
                continue;
            }

            int fail = failMap.getOrDefault(ip, 0);
            int request = requestMap.getOrDefault(ip, 0);
            int success = successMap.getOrDefault(ip, 0);
            int history = dangerHistory.getOrDefault(ip, 0);

            // Risk score formula:
            // LOGIN_FAIL x3 — strong signal of brute force
            // REQUEST x1 — normal traffic, low weight
            // LOGIN_SUCCESS -2 — reduces suspicion
            // history x5 — prior offenses multiply penalty
            int riskScore = (fail * 10)
                    + (request * 5)
                    - (success * 1)
                    + (history * 5);

            // Clamp to 0 (no negative scores)
            riskScore = Math.max(riskScore, 0);

            // Step 4: Determine attack type
            String attackType = "NORMAL";
            if (fail >= 1) {
                attackType = "BRUTE_FORCE";
            } else if (request >= 1) {
                attackType = "REQUEST_FLOOD";
            }

            // Step 5: Determine status and send alert if risky
            String status = "PASS";

            if (riskScore >= 15) {
                int level = history + 1;
                dangerHistory.put(ip, level);

                String message;

                if (riskScore >= 45) {
                    firewall.blockIP(ip);
                    status = "BLOCKED";
                    message = "🚨 CRITICAL " + attackType + " IP " + ip
                            + " | Risk Score: " + riskScore
                            + " | IP BLOCKED";

                } else if (riskScore >= 30) {
                    status = "MONITORING";
                    message = "🔴 HIGH RISK " + attackType + " IP " + ip
                            + " | Risk Score: " + riskScore;

                } else {
                    status = "SUSPICIOUS";
                    message = "⚠ Suspicious " + attackType + " IP " + ip
                            + " | Risk Score: " + riskScore;
                }

                alertSystem.addAlert(message);
            }

            // Step 6: Apply score, status, attackType to all matching log entries
            updateLogsForIP(logs, ip, riskScore, status, attackType);
        }
    }

    /**
     * Updates score, status, and attackType on all log entries belonging to a given
     * IP.
     *
     * @param logs       Full list of log entries
     * @param ip         IP address to match
     * @param riskScore  Computed risk score
     * @param status     Status label (PASS / SUSPICIOUS / MONITORING / BLOCKED)
     * @param attackType Attack type label (NORMAL / BRUTE_FORCE / REQUEST_FLOOD)
     */
    private void updateLogsForIP(List<LogEntry> logs, String ip,
            int riskScore, String status, String attackType) {
        for (LogEntry log : logs) {
            if (log.getIp().equals(ip)) {

                int currentScore = Math.max(log.getScore(), riskScore);
                String currentStatus = log.getStatus();

                // attackType luôn được cập nhật theo kết quả phân tích mới nhất
                // (tách riêng khỏi No-Downgrade rule của status)
                log.setAttackType(attackType);

                // Luật chống hạ cấp: chỉ bảo vệ status, không đụng attackType
                // Không cho phép Bot ghi đè "PASS" lên log đang ở mức SUSPICIOUS/MONITORING
                if (status.equals("PASS")
                        && (currentStatus.equals("SUSPICIOUS") || currentStatus.equals("MONITORING"))) {
                    // Giữ nguyên status lịch sử, không downgrade
                } else {
                    log.setStatus(status);
                }

                log.setScore(currentScore);
            }
        }
    }

    /**
     * Returns the Firewall instance (used by ApiServer to expose blocked IPs).
     */
    public Firewall getFirewall() {
        return firewall;
    }
}