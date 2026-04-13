package service;

import core.SecurityBot;
import model.LogEntry;
import alert.AlertSystem;
import database.DatabaseConnection;
import database.LogDAO;
import java.util.List;

/**
 * RealTimeMonitor — Multi-threaded log scanner that runs continuously.
 *
 * Implements Runnable so it can run on a separate thread alongside the API
 * server.
 * Reads logs from the database (or falls back to file) every SCAN_INTERVAL_MS
 * milliseconds,
 * runs SecurityBot analysis, and persists the results back to the database.
 */
public class RealTimeMonitor implements Runnable {

    // Shared bot and alert system instances
    private SecurityBot bot;
    private AlertSystem alertSystem;

    // Scan DB 2s một lần
    private static final int SCAN_INTERVAL_MS = 2000;

    /**
     * Constructor: stores shared bot and alert system references.
     */
    public RealTimeMonitor(SecurityBot bot, AlertSystem alertSystem) {
        this.bot = bot;
        this.alertSystem = alertSystem;
    }

    /**
     * Thread run loop: scans logs every SCAN_INTERVAL_MS milliseconds.
     * Priority: read from database, fallback to file if DB is empty.
     */
    @Override
    public void run() {

        System.out.println("[RealTimeMonitor] Started. Scanning logs every 2s...");

        LogReader reader = new LogReader();
        // [FIX LỖI 5] Khởi tạo LogDAO để đọc từ DB khi có kết nối
        LogDAO logDAO = new LogDAO();

        try {
            while (true) {

                try {
                    List<LogEntry> logs;

                    // Priority: read from DB; fallback to file ONLY if DB is unavailable.
                    // Do NOT fallback to file when DB is empty — LogGenerator will populate it
                    // shortly.
                    if (DatabaseConnection.isAvailable()) {
                        logs = logDAO.getAllLogs();
                        System.out.println("[Monitor] Read " + logs.size() + " log(s) from DATABASE");
                    } else {
                        // DB unavailable — try the text file as last resort
                        logs = reader.readLog("logs/network.log");
                        System.out.println("[Monitor] Read " + logs.size() + " log(s) from FILE");
                    }

                    if (logs != null && !logs.isEmpty()) {
                        bot.analyze(logs, alertSystem);

                        // Persist analysis results (attack_type, status) back to DB.
                        // Without this step, analyze() results only live in RAM.
                        if (DatabaseConnection.isAvailable()) {
                            logDAO.updateLogs(logs);
                        }

                        int start = Math.max(0, logs.size() - 5);
                        List<LogEntry> recent = logs.subList(start, logs.size());
                        System.out.println("--- Last 5 Log Entries ---");
                        for (LogEntry l : recent) {
                            System.out.println(l.getTime() + " | IP: " + l.getIp() + " | Attack: " + l.getAttackType()
                                    + " | Risk: " + l.getScore());
                        }
                    } else {
                        System.out.println("[Monitor] No logs available yet.");
                    }

                } catch (Exception e) {
                    System.err.println("[RealTimeMonitor] Error in scan loop: " + e.getMessage());
                }

                Thread.sleep(SCAN_INTERVAL_MS);
            }

        } catch (InterruptedException e) {
            System.out.println("[RealTimeMonitor] Thread interrupted. Exiting.");
            Thread.currentThread().interrupt();
        }
    }
}