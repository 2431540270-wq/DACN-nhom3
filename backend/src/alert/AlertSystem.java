package alert;

import java.util.*;

import database.DatabaseConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;

/**
 * AlertSystem — Lưu trữ cảnh báo bảo mật vào DB và giữ bản sao in-memory.
 *
 * Cấu trúc:
 * - In-memory list: dùng làm fallback khi DB không khả dụng (được ApiServer
 *   đọc qua getAlerts() cho endpoint /api/alerts khi DB unavailable).
 * - Database (bảng alerts): nguồn dữ liệu chính cho /api/alerts khi DB online.
 *
 * Đã xóa:
 * - saveAlertToFile() / loadAlertsFromFile() — không cần thiết vì DB đã persist.
 * - ALERT_FILE constant và thư mục alerts/ — không còn sử dụng.
 */
public class AlertSystem {

    /**
     * Thread-safe alert list — dùng làm fallback khi DB không khả dụng.
     * ApiServer (read) và RealTimeMonitor (write) truy cập đồng thời.
     */
    private List<String> alerts = Collections.synchronizedList(new ArrayList<>());

    /**
     * Lưu một cảnh báo vào DB (bảng alerts).
     */
    private void saveAlertToDatabase(String ip, String attackType, int riskScore,
                                     String alertLevel, String message) {
        String sql = "INSERT INTO alerts (ip_address, attack_type, risk_score, alert_level, message) "
                   + "VALUES (?, ?, ?, ?, ?)";
        try (Connection conn  = DatabaseConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, ip);
            ps.setString(2, attackType);
            ps.setInt   (3, riskScore);
            ps.setString(4, alertLevel);
            ps.setString(5, message);
            ps.executeUpdate();

        } catch (Exception e) {
            System.err.println("[AlertSystem] DB insert failed: " + e.getMessage());
        }
    }

    /**
     * Thêm một cảnh báo mới: lưu vào in-memory list và DB.
     * In-memory list tự giới hạn 500 entries để tránh memory leak.
     *
     * @param ip         IP address của kẻ tấn công
     * @param attackType Loại tấn công: BRUTE_FORCE / REQUEST_FLOOD / ...
     * @param riskScore  Điểm rủi ro đã tính
     * @param status     Trạng thái: SUSPICIOUS / MONITORING / BLOCKED
     */
    public void addAlert(String ip, String attackType, int riskScore, String status) {

        // Xác định alert level và message dựa trên riskScore
        String alertLevel;
        String message;

        if (riskScore >= 45) {
            alertLevel = "CRITICAL";
            message = "🚨 CRITICAL " + attackType + " IP " + ip
                    + " | Risk Score: " + riskScore
                    + " | IP BLOCKED";

        } else if (riskScore >= 30) {
            alertLevel = "HIGH";
            message = "🔴 HIGH RISK " + attackType + " IP " + ip
                    + " | Risk Score: " + riskScore;

        } else {
            alertLevel = "MEDIUM";
            message = "⚠ Suspicious " + attackType + " IP " + ip
                    + " | Risk Score: " + riskScore;
        }

        String timeStampedMessage = "[" + new Date().toString() + "] " + message;

        // Giữ trong memory (dùng làm fallback khi DB unavailable)
        synchronized (alerts) {
            if (alerts.size() >= 500) {
                alerts.subList(0, 50).clear(); // Xóa 50 cái cũ nhất
            }
            alerts.add(timeStampedMessage);
        }

        // Lưu vào DB — nguồn chính cho /api/alerts
        if (DatabaseConnection.isAvailable()) {
            saveAlertToDatabase(ip, attackType, riskScore, alertLevel, timeStampedMessage);
        }

        System.out.println(timeStampedMessage);
    }

    /**
     * Trả về bản sao danh sách alert in-memory.
     * Được ApiServer dùng làm fallback khi DB không sẵn sàng.
     */
    public List<String> getAlerts() {
        return new ArrayList<>(alerts);
    }

    /**
     * Xóa toàn bộ alerts khỏi memory.
     */
    public void clearAlerts() {
        alerts.clear();
    }
}