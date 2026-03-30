package main;

import core.SecurityBot;
import alert.AlertSystem;
import service.RealTimeMonitor;
import database.DatabaseConnection;
import service.LogGenerator;

/**
 * Main — Entry point khởi động hệ thống AI Security IDS.
 *
 * Luồng khởi động:
 * 1. Kiểm tra kết nối MySQL Database
 * 2. Tạo shared SecurityBot + AlertSystem
 * 3. Khởi động RealTimeMonitor (daemon thread)
 * 4. Khởi động ApiServer (port 8080)
 *
 * Nếu MySQL không khả dụng → hệ thống vẫn chạy bằng file text.
 */
public class Main {
    public static void main(String[] args) {

        System.out.println("============================================");
        System.out.println("🛡️  AI Security IDS - Khởi động hệ thống");
        System.out.println("============================================");

        try {
            // BƯỚC 1: Kiểm tra MySQL Database
            System.out.println("\n[Bước 1] Kiểm tra kết nối MySQL...");
            boolean dbOk = DatabaseConnection.testConnection();

            if (!dbOk) {
                System.out.println("   MySQL không khả dụng → Dùng file text làm nguồn dữ liệu");
                System.out.println("   Để dùng MySQL: chạy database/setup.sql và thêm JDBC driver");
            }

            // BƯỚC 2: Khởi tạo shared instances
            System.out.println("\n[Bước 2] Khởi tạo SecurityBot + AlertSystem...");
            SecurityBot bot = new SecurityBot();
            AlertSystem alertSystem = new AlertSystem();
            System.out.println("✅ SecurityBot + AlertSystem sẵn sàng (shared instance)");

            // BƯỚC 3: Khởi động RealTimeMonitor và LogGenerator
            System.out.println("\n[Bước 3] Khởi động RealTimeMonitor...");
            RealTimeMonitor monitor = new RealTimeMonitor(bot, alertSystem);
            Thread monitorThread = new Thread(monitor, "RealTimeMonitor-Thread");
            monitorThread.setDaemon(true);
            monitorThread.start();
            System.out.println("✅ RealTimeMonitor đang chạy (quét mỗi 3 giây)");
            System.out.println("\nKhởi động LogGenerator...");
            new Thread(() -> {
                new LogGenerator().startGenerating();
            }, "LogGenerator-Thread").start();
            System.out.println("✅ LogGenerator đang chạy (tạo log mỗi giây)");

            // BƯỚC 4: Khởi động API Server
            System.out.println("\n[Bước 4] Khởi động API Server...");
            ApiServer.startServer(bot, alertSystem);

            // Tổng kết
            System.out.println("\n============================================");
            System.out.println("   HỆ THỐNG ĐÃ SẴN SÀNG!");
            System.out.println("   API:      http://localhost:8080");
            System.out.println("   Database: " + (dbOk ? "MySQL (connected)" : "File text (fallback)"));
            System.out.println("   Frontend: Mở frontend/dashboard.html");
            System.out.println("============================================\n");

        } catch (Exception e) {
            System.err.println("💥 LỖI KHỞI ĐỘNG: " + e.getMessage());
            e.printStackTrace();
        }
    }
}