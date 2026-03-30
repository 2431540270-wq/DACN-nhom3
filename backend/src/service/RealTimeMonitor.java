package service;

import core.SecurityBot;
import model.LogEntry;
import alert.AlertSystem;
import database.DatabaseConnection;
import database.LogDAO;
import java.util.List;

/**
 * LỚP: RealTimeMonitor (Kẻ Canh Gác Chống Ngủ Gật Đa Luồng).
 * 
 * Giải Cứu Newbie: Runnable là khái niệm THREAD (Luồng / Đa Nhiệm).
 * Nếu Java chỉ chạy 1 hàng từ trên xuống dưới, bạn không thể vừa Mở Máy Chủ API (chờ khách) 
 * mà vừa soi File Liên Tục Đếm Số được! (Đường 1 làn sẽ kẹt xe nhau).
 * 
 * Rẽ Binh Nhách: implements Runnable giúp cái tay giám sát này chạy "Chếch hướng" song song
 * với hàm Main. Không ai phá ai.
 */
public class RealTimeMonitor implements Runnable {
    
    // Giữ sẵn Con Bot với Còi Báo Động. Lát gặp cướp thì báo
    private SecurityBot bot;
    private AlertSystem alertSystem;

    // Chu kỳ Thức dậy Lặp (3000ms = 3 giây).
    // Nếu bạn set cái này là 0 -> Cái Vòng Lặp While chéo nghẹt Máy Tính "100% CPU" cháy CPU Mainboard đó!
    private static final int SCAN_INTERVAL_MS = 3000;

    /**
     * Dàn quân Nạp Cấu Hình Khi Khởi Thủy Monitor.
     */
    public RealTimeMonitor(SecurityBot bot, AlertSystem alertSystem) {
        this.bot = bot;
        this.alertSystem = alertSystem;
    }

    /**
     * HÀM RÚT LÕI (OVERRIDE CỦA RUNNABLE THREAD).
     * Hàm này luôn chạy độc lập ở một Cổng Vũ Trụ Multi-Core xử lý riêng biệtt. 
     */
    @Override
    public void run() {

        System.out.println("🤖 Mắt Thần RealTimeMonitor đã vào vị trí. Quét Log mỗi 3s...");

        LogReader reader = new LogReader();
        // [FIX LỖI 5] Khởi tạo LogDAO để đọc từ DB khi có kết nối
        LogDAO logDAO = new LogDAO();

        try {
            while (true) {
                
                try {
                    List<LogEntry> logs;

                    // [FIX LỖI 5] ƯU TIÊN đọc từ DB, FALLBACK file text
                    if (DatabaseConnection.isAvailable()) {
                        logs = logDAO.getAllLogs();
                        if (logs.isEmpty()) {
                            // DB trống → thử đọc file
                            logs = reader.readLog("logs/network.log");
                        }
                        System.out.println("[Monitor] Đọc " + logs.size() + " log từ DATABASE");
                    } else {
                        logs = reader.readLog("logs/network.log");
                        System.out.println("[Monitor] Đọc " + logs.size() + " log từ FILE");
                    }
                    
                    if (logs != null && !logs.isEmpty()) {
                        bot.analyze(logs, alertSystem);
                        
                        int start = Math.max(0, logs.size() - 5);
                        List<LogEntry> recent = logs.subList(start, logs.size());
                        System.out.println("--- 5 Dòng Log Mới Nhất Vừa Quét ---");
                        for (LogEntry l : recent) {
                            System.out.println(l.getTime() + " | IP: " + l.getIp() + " | Attack: " + l.getAttackType() + " | Risk: " + l.getScore());
                        }
                    } else {
                        System.out.println("[Monitor] Chưa có log nào trong hệ thống.");
                    }

                } catch (Exception e) {
                    System.err.println("❌ Lỗi RealTimeMonitor (vòng lặp): " + e.getMessage());
                }

                Thread.sleep(SCAN_INTERVAL_MS);
            }
            
        } 
        catch (InterruptedException e) {
            System.out.println("⚠️ Luồng RealTimeMonitor bị ngắt. Thoát dứt điểm!");
            Thread.currentThread().interrupt(); // Restore interrupt flag
        }
    }
}