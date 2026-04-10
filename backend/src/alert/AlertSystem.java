package alert;

import java.io.*;
import java.util.*;

import database.DatabaseConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;

/**
 * AlertSystem — Stores and persists security alert messages.
 *
 * Responsibilities:
 * - Hold alerts in an in-memory thread-safe list (used by API to serve
 * frontend)
 * - Append each new alert to a text file on disk for persistence
 * - Load existing alerts from file on startup
 */
public class AlertSystem {

    /**
     * Thread-safe alert list.
     * Both ApiServer (read) and RealTimeMonitor (write) access this concurrently,
     * so Collections.synchronizedList() prevents ConcurrentModificationException.
     */
    private List<String> alerts = Collections.synchronizedList(new ArrayList<>());

    // Path to the persistent alert log file
    private final String ALERT_FILE = "alerts/alert.txt";

    /**
     * [BUG 4 FIX] Dùng try-with-resources để đảm bảo Connection và PreparedStatement
     *             luôn được đóng, tránh connection pool bị cạn kiệt.
     * [BUG 5 FIX] INSERT đủ các cột theo schema DB:
     *             ip_address, attack_type, risk_score, alert_level, message
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
     * Constructor: loads existing alerts from file into memory on startup.
     * Also ensures the alerts/ directory exists so file writes never fail.
     */
    public AlertSystem() {
        // Create alerts/ directory if it does not exist yet
        new File(ALERT_FILE).getParentFile().mkdirs();
        loadAlertsFromFile();
    }

    /**
     * Adds a new alert message (timestamped) to the in-memory list and appends it
     * to file.
     * Automatically evicts the oldest 50 entries when the list exceeds 500 to
     * prevent memory leak.
     *
     * @param message Alert message (e.g. "🚨 CRITICAL BRUTE_FORCE IP 192.168.1.15 |
     *                Risk Score: 45")
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

        // Limit in-memory alerts to 500 entries (system runs 24/7)
        synchronized (alerts) {
            if (alerts.size() >= 500) {
                alerts.subList(0, 50).clear(); // Batch-remove oldest 50
            }
            alerts.add(timeStampedMessage);
        }

        saveAlertToFile(timeStampedMessage);
        // [BUG 4+5 FIX] Truyền đủ tham số theo schema DB
        saveAlertToDatabase(ip, attackType, riskScore, alertLevel, timeStampedMessage);

        System.out.println(timeStampedMessage);
    }

    /**
     * Returns a snapshot copy of all current alerts.
     * Returns a copy to avoid ConcurrentModificationException in callers.
     */
    public List<String> getAlerts() {
        return new ArrayList<>(alerts);
    }

    /**
     * Clears all alerts from memory (does not delete the file).
     */
    public void clearAlerts() {
        alerts.clear();
    }

    /**
     * Appends a single alert message to the alert file (append mode — never
     * overwrites).
     */
    private void saveAlertToFile(String message) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(ALERT_FILE, true))) {
            writer.write(message);
            writer.newLine();
        } catch (IOException e) {
            System.err.println("[AlertSystem] Failed to write alert to file: " + e.getMessage());
        }
    }

    /**
     * Reads all previously saved alert lines from disk into the in-memory list.
     * Called once during construction. Skips silently if file does not exist yet.
     */
    private void loadAlertsFromFile() {
        File file = new File(ALERT_FILE);
        if (!file.exists()) {
            return;
        }

        alerts.clear();

        try (BufferedReader reader = new BufferedReader(new FileReader(ALERT_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                alerts.add(line);
            }
        } catch (IOException e) {
            System.err.println("[AlertSystem] Failed to load alerts from file: " + e.getMessage());
        }
    }
}