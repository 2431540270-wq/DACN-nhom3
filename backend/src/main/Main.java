package main;

import core.SecurityBot;
import alert.AlertSystem;
import service.RealTimeMonitor;
import database.DatabaseConnection;
import service.LogGenerator;

/**
 * Main — Entry point for the AI Security IDS system.
 *
 * Startup sequence:
 *   1. Test MySQL database connection
 *   2. Create shared SecurityBot + AlertSystem instances
 *   3. Start RealTimeMonitor (daemon thread — scans logs every 3s)
 *   4. Start LogGenerator (daemon thread — inserts a new log every 1s)
 *   5. Start ApiServer (port 8080 — serves the frontend)
 *
 * If MySQL is unavailable, the system falls back to reading from the text file.
 */
public class Main {
    public static void main(String[] args) {

        System.out.println("============================================");
        System.out.println("   AI Security IDS - Starting up");
        System.out.println("============================================");

        try {
            // STEP 1: Check MySQL connection
            System.out.println("\n[Step 1] Testing MySQL connection...");
            boolean dbOk = DatabaseConnection.testConnection();

            if (!dbOk) {
                System.out.println("   MySQL unavailable -> Using text file as data source");
                System.out.println("   To enable MySQL: run database/setup.sql and add the JDBC driver");
            }

            // STEP 2: Create shared instances
            System.out.println("\n[Step 2] Initializing SecurityBot + AlertSystem...");
            SecurityBot bot = new SecurityBot();
            AlertSystem alertSystem = new AlertSystem();
            System.out.println("   SecurityBot + AlertSystem ready");

            // STEP 3: Start RealTimeMonitor
            System.out.println("\n[Step 3] Starting RealTimeMonitor...");
            RealTimeMonitor monitor = new RealTimeMonitor(bot, alertSystem);
            Thread monitorThread = new Thread(monitor, "RealTimeMonitor-Thread");
            monitorThread.setDaemon(true);
            monitorThread.start();
            System.out.println("   RealTimeMonitor started (scan interval: 3s)");

            // STEP 4: Start LogGenerator
            System.out.println("\n[Step 4] Starting LogGenerator...");
            new Thread(() -> {
                new LogGenerator().startGenerating();
            }, "LogGenerator-Thread").start();
            System.out.println("   LogGenerator started (1 log per second)");

            // STEP 5: Start API Server
            System.out.println("\n[Step 5] Starting API Server...");
            ApiServer.startServer(bot, alertSystem);

            // Summary
            System.out.println("\n============================================");
            System.out.println("   SYSTEM READY");
            System.out.println("   API:      http://localhost:8080");
            System.out.println("   Database: " + (dbOk ? "MySQL (connected)" : "File text (fallback)"));
            System.out.println("   Frontend: Open frontend/dashboard.html");
            System.out.println("============================================\n");

        } catch (Exception e) {
            System.err.println("[Main] Startup error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}