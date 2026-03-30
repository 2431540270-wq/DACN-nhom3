package alert;

import java.io.*;
import java.util.*;

/**
 * AlertSystem — Stores and persists security alert messages.
 *
 * Responsibilities:
 *   - Hold alerts in an in-memory thread-safe list (used by API to serve frontend)
 *   - Append each new alert to a text file on disk for persistence
 *   - Load existing alerts from file on startup
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
     * Constructor: loads existing alerts from file into memory on startup.
     * Also ensures the alerts/ directory exists so file writes never fail.
     */
    public AlertSystem() {
        // Create alerts/ directory if it does not exist yet
        new File(ALERT_FILE).getParentFile().mkdirs();
        loadAlertsFromFile();
    }

    /**
     * Adds a new alert message (timestamped) to the in-memory list and appends it to file.
     * Automatically evicts the oldest 50 entries when the list exceeds 500 to prevent memory leak.
     *
     * @param message Alert message (e.g. "🚨 CRITICAL BRUTE_FORCE IP 192.168.1.15 | Risk Score: 45")
     */
    public void addAlert(String message) {

        String timeStampedMessage = "[" + new Date().toString() + "] " + message;

        // Limit in-memory alerts to 500 entries (system runs 24/7)
        synchronized (alerts) {
            if (alerts.size() >= 500) {
                alerts.subList(0, 50).clear(); // Batch-remove oldest 50
            }
            alerts.add(timeStampedMessage);
        }

        saveAlertToFile(timeStampedMessage);

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
     * Appends a single alert message to the alert file (append mode — never overwrites).
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