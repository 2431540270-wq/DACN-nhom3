package core;

import java.util.*;
import model.LogEntry;
import alert.AlertSystem;
import service.LogAnalyzer;

public class SecurityBot {

    private Map<String, Integer> dangerHistory = new HashMap<>();

    /**
     * Số lượng LOGIN_FAIL và REQUEST đã được phân tích ở chu kỳ trước.
     * dangerHistory chỉ tăng khi fail/request count TĂNG LÊN (có log mới).
     * Nếu count giữ nguyên (cùng log cũ trong DB), không tăng history.
     */
    private Map<String, Integer> lastFailCount = new HashMap<>();
    private Map<String, Integer> lastRequestCount = new HashMap<>();

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
    public synchronized void analyze(List<LogEntry> logs, AlertSystem alertSystem) {

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
        // Giữ lại state cho các IP cũ (tránh reset về 0/-1)
        Set<String> existingIPs = new HashSet<>(lastFailCount.keySet());

        for (String oldIp : existingIPs) {
            if (!allIPs.contains(oldIp)) {
                // giữ nguyên giá trị cũ, KHÔNG xóa
                lastFailCount.put(oldIp, lastFailCount.get(oldIp));
                lastRequestCount.put(oldIp, lastRequestCount.getOrDefault(oldIp, 0));
            }
        }
        // Step 3: Evaluate each IP
        for (String ip : allIPs) {

            if (firewall.isBlocked(ip)) {
                for (LogEntry log : logs) {
                    if (log.getIp().equals(ip)) {
                        log.setScore(90);
                        log.setStatus("BLOCKED");
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

            // So sánh với snapshot chu kỳ trước:
            // - Default -1: lần đầu thấy IP, LUÔN hasNewActivity=true → detect đúng ngay
            // cycle 1.
            // (fail=2 > -1 → true → alert 1 lần đúng lúc)
            // - Cycle 2+: prevFail=2, fail=2 → (2>2)=false → NO alert ← đây là điểm mấu
            // chốt.
            // containsKey() bị bỏ vì: có blind spot 2s đầu và bị re-trigger khi log
            // ra/vào top-100 window (prevFail bị reset về 0, rồi fail=2 > 0 → sai).
            int prevFail = lastFailCount.getOrDefault(ip, 0);
            int prevRequest = lastRequestCount.getOrDefault(ip, 0);
            boolean hasNewActivity = (fail > prevFail) || (request > prevRequest);

            // Luôn cập nhật snapshot cho chu kỳ tiếp theo
            lastFailCount.put(ip, fail);
            lastRequestCount.put(ip, request);

            // Risk score formula:
            // LOGIN_FAIL x10 — strong signal of brute force
            // REQUEST x5 — flood traffic
            // SUCCESS x1 — reduces suspicion
            // history x5 — prior offense multiplier (chỉ tăng khi có activity mới)
            int riskScore = (fail * 10)
                    + (request * 5)
                    - (success * 1)
                    + (history * 5);
            riskScore = Math.max(riskScore, 0);

            // Step 4: Determine attack type
            String attackType = "NORMAL";
            if (fail >= 1) {
                attackType = "BRUTE_FORCE";
            } else if (request >= 1) {
                attackType = "REQUEST_FLOOD";
            }

            // Step 5: Chỉ leo thang (history, alert, block) khi có LOG MỚI.
            // Không có log mới → cùng bộ log cũ trong DB → không tạo thêm alert,
            // không tự block, không tăng history. Status giữ nguyên nhờ no-downgrade rule.
            String status = "PASS";

            if (riskScore >= 15 && hasNewActivity) {
                int level = Math.min(history + 1, 10);
                dangerHistory.put(ip, level);

                if (riskScore >= 45) {
                    firewall.blockIP(ip);
                    status = "BLOCKED";

                } else if (riskScore >= 30) {
                    status = "MONITORING";

                } else {
                    status = "SUSPICIOUS";
                }

                alertSystem.addAlert(ip, attackType, riskScore, status);
            }

            // Step 6: Cập nhật score và status lên các log entries của IP.
            // status="PASS" khi không có activity mới → no-downgrade rule giữ nguyên
            // SUSPICIOUS/MONITORING hiện tại, không downgrade.
            updateLogsForIP(logs, ip, riskScore, status, attackType);
        }
    }

    /*
     * 
     * Updates score, status, and attackType on all log entries belonging to a given
     * IP.
     * 
     * 
     * 
     * @param logs Full list of log entries
     * 
     * @param ip IP address to match
     * 
     * @param riskScore Computed risk score
     * 
     * @param status Status label (PASS / SUSPICIOUS / MONITORING / BLOCKED)
     * 
     * @param attackType Attack type label (NORMAL / BRUTE_FORCE / REQUEST_FLOOD)
     */
    private void updateLogsForIP(List<LogEntry> logs, String ip,
            int riskScore, String status, String attackType) {
        for (LogEntry log : logs) {
            if (log.getIp().equals(ip)) {

                int currentScore = Math.max(log.getScore(), riskScore);
                String currentStatus = log.getStatus();

                // Mỗi log giữ nguyên attack_type gốc được set lúc INSERT:
                // - LOGIN_FAIL log → BRUTE_FORCE (set bởi /api/attack/bruteforce)
                // - REQUEST log → REQUEST_FLOOD (set bởi /api/attack/flood)
                // - Log thường → NORMAL
                // attackType (tham số) chỉ dùng cho alertSystem.addAlert() ở trên,
                // không áp đặt lên từng bản ghi DB nữa.

                // Luật chống hạ cấp status:
                // Không cho phép ghi đè "PASS" lên log đang ở mức SUSPICIOUS/MONITORING
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
     * Xóa lịch sử nguy hiểm (dangerHistory) của một IP cụ thể.
     *
     * Được gọi khi admin gỡ block IP từ /api/unblock.
     * Nếu không xóa dangerHistory, analyze() sẽ đọc score lịch sử cao
     * và re-block IP sau ~2 giây ngay cả khi đã gỡ block.
     *
     * @param ip IP address cần xóa lịch sử
     */
    public synchronized void clearHistory(String ip) {
        dangerHistory.remove(ip);
        lastFailCount.remove(ip); // Reset snapshot để IP bắt đầu lại hoàn toàn
        lastRequestCount.remove(ip);
        System.out.println("[SecurityBot] Cleared danger history for IP: " + ip);
    }

    /**
     * Returns the Firewall instance (used by ApiServer to expose blocked IPs).
     */
    public Firewall getFirewall() {
        return firewall;
    }
}