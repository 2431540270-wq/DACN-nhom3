package main;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

import service.LogReader;
import model.LogEntry;
import core.SecurityBot;
import alert.AlertSystem;
import database.DatabaseConnection;
import database.LogDAO;

/**
 * ApiServer — Máy chủ API phục vụ Frontend.
 *
 * Port: 8080 (http://localhost:8080)
 *
 * [UPGRADE] Hỗ trợ 2 nguồn dữ liệu:
 * - Ưu tiên 1: MySQL Database (qua LogDAO)
 * - Ưu tiên 2: File text (qua LogReader) — fallback nếu DB chết
 *
 * Endpoints:
 * GET /api/analyze — Phân tích log, tính risk score
 * GET /api/logs — Lấy 100 dòng log mới nhất
 * GET /api/alerts — Lấy danh sách cảnh báo
 * GET /api/blocked — Lấy danh sách IP bị chặn
 */
public class ApiServer {

    private static List<LogEntry> logs = new ArrayList<>();
    private static AlertSystem alertSystem;
    private static SecurityBot bot;
    private static LogDAO logDAO = new LogDAO();
    // [FIX LỖI 1+2] Đã xóa field logGenerator static — LogGenerator được khởi động
    // duy nhất 1 lần từ Main.java. Giữ 2 instance sẽ gây duplicate insert vào DB.

    /**
     * Khởi tạo API Server.
     *
     * @param sharedBot         SecurityBot dùng chung
     * @param sharedAlertSystem AlertSystem dùng chung
     */
    public static void startServer(SecurityBot sharedBot, AlertSystem sharedAlertSystem) throws Exception {

        bot = sharedBot;
        alertSystem = sharedAlertSystem;

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        // ============================================================
        // API 1: PHÂN TÍCH LOG (GET /api/analyze)
        // ============================================================
        server.createContext("/api/analyze", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                // ƯU TIÊN 1: Đọc từ Database
                if (DatabaseConnection.isAvailable()) {
                    logs = logDAO.getAllLogs();
                    System.out.println("[API /analyze] Đọc từ DATABASE: " + logs.size() + " dòng");
                } else {
                    // FALLBACK: Đọc từ file text
                    LogReader reader = new LogReader();
                    logs = reader.readLog("logs/network.log");
                    if (logs == null)
                        logs = new ArrayList<>();
                    System.out.println("[API /analyze] Đọc từ FILE: " + logs.size() + " dòng");
                }

                // [FIX LỖI 7] Không clear toàn bộ alerts — chỉ re-analyze để update trạng thái
                // clearAlerts() sẽ làm mất hết alert cũ mỗi giây — giữ lại,
                // SecurityBot.analyze()
                // sẽ tự thêm alert mới vào list
                bot.analyze(logs, alertSystem);

                // [FIX LỖI 3] ĐÃ XÓA logDAO.insertLogs(logs) TẠI ĐÂY
                // LogGenerator đã responsible cho việc insert log mỗi giây.
                // Nếu insert thêm ở đây → mỗi lần /analyze call sẽ duplicate toàn bộ 100 bản
                // ghi vào DB!

                // [FIX LỖI 6] Tách biệt totalLogs (để hiển thị) vs tính riskAvg
                // totalLogs = tổng số log trong DB (chính xác)
                // riskAvg = trung bình score của 100 bản ghi đọc được (tính được)
                int displayTotal = logs.size();
                double riskAvg = 0;

                // Nếu có DB, lấy tổng count thật từ DB
                if (DatabaseConnection.isAvailable()) {
                    int dbCount = logDAO.getLogCount();
                    if (dbCount > displayTotal)
                        displayTotal = dbCount;
                }

                if (!logs.isEmpty()) {
                    int totalRisk = 0;
                    for (LogEntry l : logs) {
                        totalRisk += l.getScore();
                    }
                    // Chia cho logs.size() (100 bản ghi), KHÔNG chia cho displayTotal
                    riskAvg = Math.round((double) totalRisk / logs.size() * 10.0) / 10.0;
                }

                // Dùng displayTotal (tổng DB) cho JSON response, không phải logs.size()
                int totalLogs = displayTotal;

                String response = "{\"status\":\"analyzed\",\"totalLogs\":" + totalLogs
                        + ",\"riskAvg\":" + riskAvg + "}";

                System.out.println("[API /analyze] Response: " + response);
                sendJson(exchange, response);

            } catch (Exception e) {
                System.err.println("[API /analyze] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // ============================================================
        // API 2: LẤY LOGS (GET /api/logs)
        // ============================================================
        server.createContext("/api/logs", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                // ƯU TIÊN: Đọc từ Database nếu có
                List<LogEntry> logsToSend = logs;
                if (DatabaseConnection.isAvailable()) {
                    List<LogEntry> dbLogs = logDAO.getAllLogs();
                    if (!dbLogs.isEmpty()) {
                        logsToSend = dbLogs;
                    }
                }

                StringBuilder json = new StringBuilder("[");
                int limit = Math.min(logsToSend.size(), 100);

                for (int i = 0; i < limit; i++) {
                    LogEntry l = logsToSend.get(i);
                    json.append("{")
                            .append("\"time\":\"").append(escapeJson(l.getTime())).append("\",")
                            .append("\"ip\":\"").append(escapeJson(l.getIp())).append("\",")
                            .append("\"action\":\"").append(escapeJson(l.getAction())).append("\",")
                            .append("\"attack\":\"").append(escapeJson(l.getAttackType())).append("\",")
                            .append("\"score\":").append(l.getScore()).append(",")
                            .append("\"status\":\"").append(escapeJson(l.getStatus())).append("\"")
                            .append("}");
                    if (i < limit - 1)
                        json.append(",");
                }
                json.append("]");

                System.out.println("[API /logs] Trả về " + limit + " dòng");
                sendJson(exchange, json.toString());

            } catch (Exception e) {
                System.err.println("[API /logs] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // ============================================================
        // API 3: LẤY ALERTS (GET /api/alerts)
        // ============================================================
        server.createContext("/api/alerts", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                List<String> alerts = alertSystem.getAlerts();
                System.out.println("[API /alerts] Có " + alerts.size() + " cảnh báo");

                StringBuilder json = new StringBuilder("[");
                for (int i = 0; i < alerts.size(); i++) {
                    String alert = alerts.get(i);

                    String level = "LOW";
                    String attack = "UNKNOWN";
                    String ip = "0.0.0.0";
                    int score = 10;

                    if (alert.contains("🚨")) {
                        level = "CRITICAL";
                        score = 90;
                    } else if (alert.contains("🔴")) {
                        level = "HIGH";
                        score = 70;
                    } else if (alert.contains("⚠")) {
                        level = "MEDIUM";
                        score = 50;
                    }

                    if (alert.contains("BRUTE_FORCE"))
                        attack = "BRUTE_FORCE";
                    else if (alert.contains("REQUEST_FLOOD"))
                        attack = "REQUEST_FLOOD";

                    // Tìm IP bằng regex
                    String[] parts = alert.split(" ");
                    for (String p : parts) {
                        if (p.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                            ip = p;
                        }
                    }

                    // Lấy thời gian giữa [ và ]
                    String time = "";
                    if (alert.contains("]")) {
                        int startIdx = alert.indexOf("[");
                        int endIdx = alert.indexOf("]");
                        if (startIdx >= 0 && endIdx > startIdx) {
                            time = alert.substring(startIdx + 1, endIdx);
                        }
                    }

                    json.append("{")
                            .append("\"time\":\"").append(escapeJson(time)).append("\",")
                            .append("\"level\":\"").append(escapeJson(level)).append("\",")
                            .append("\"attack\":\"").append(escapeJson(attack)).append("\",")
                            .append("\"ip\":\"").append(escapeJson(ip)).append("\",")
                            .append("\"score\":").append(score)
                            .append("}");

                    if (i < alerts.size() - 1)
                        json.append(",");
                }
                json.append("]");

                sendJson(exchange, json.toString());

            } catch (Exception e) {
                System.err.println("[API /alerts] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // ============================================================
        // API 4: DANH SÁCH IP BỊ CHẶN (GET /api/blocked)
        // ============================================================
        server.createContext("/api/blocked", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                // [FIX LỖI 13] Lấy snapshot thay vì reference trực tiếp → tránh
                // ConcurrentModificationException
                // khi Firewall.blockIP() được gọi từ thread khác trong lúc đang duyệt set
                Set<String> ipsSnapshot = new java.util.HashSet<>(bot.getFirewall().getBlockedIPs());
                System.out.println("[API /blocked] " + ipsSnapshot.size() + " IP bị chặn");

                StringBuilder json = new StringBuilder("[");
                int i = 0;
                for (String ip : ipsSnapshot) {
                    json.append("\"").append(escapeJson(ip)).append("\"");
                    if (i < ipsSnapshot.size() - 1)
                        json.append(",");
                    i++;
                }
                json.append("]");

                sendJson(exchange, json.toString());

            } catch (Exception e) {
                System.err.println("[API /blocked] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // ============================================================
        // API 5: BLOCK IP THỦ CÔNG (POST /api/block)
        // ============================================================
        server.createContext("/api/block", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                // Đọc body POST: { "ip": "192.168.1.1" }
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String ip = extractJsonField(body, "ip");

                if (ip == null || ip.isEmpty() || !ip.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
                    byte[] err = "{\"success\":false,\"message\":\"IP không hợp lệ\"}".getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(400, err.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(err);
                    }
                    return;
                }

                bot.getFirewall().blockIP(ip);
                System.out.println("[API /block] Đã BLOCK IP thủ công: " + ip);
                sendJson(exchange, "{\"success\":true,\"message\":\"Đã chặn IP " + escapeJson(ip) + "\"}");

            } catch (Exception e) {
                System.err.println("[API /block] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // ============================================================
        // API 6: GỠ CHẶN IP (POST /api/unblock)
        // ============================================================
        server.createContext("/api/unblock", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String ip = extractJsonField(body, "ip");

                if (ip == null || ip.isEmpty()) {
                    byte[] err = "{\"success\":false,\"message\":\"IP không hợp lệ\"}".getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(400, err.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(err);
                    }
                    return;
                }

                bot.getFirewall().unblockIP(ip);
                System.out.println("[API /unblock] Đã GỠ CHẶN IP: " + ip);
                sendJson(exchange, "{\"success\":true,\"message\":\"Đã gỡ chặn IP " + escapeJson(ip) + "\"}");

            } catch (Exception e) {
                System.err.println("[API /unblock] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // [FIX LỖI 1+2] ĐÃ XÓA: Thread khởi động LogGenerator lần 2 ở đây.
        // LogGenerator được khởi động DUY NHẤT 1 lần từ Main.java (Bước 3).
        server.start();
        System.out.println("✅ API Server running at http://localhost:8080");
        System.out
                .println("   Endpoints: /api/analyze, /api/logs, /api/alerts, /api/blocked, /api/block, /api/unblock");
        System.out.println(
                "   Data source: " + (DatabaseConnection.isAvailable() ? "MySQL Database" : "File text (fallback)"));
    }

    // ============================================================
    // HÀM PHỤ TRỢ
    // ============================================================

    /** Xử lý CORS — cho phép Frontend gọi API từ domain/port khác */
    private static boolean handleCors(HttpExchange exchange) throws Exception {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");

        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return true;
        }
        return false;
    }

    /** Gửi JSON response về cho Frontend */
    private static void sendJson(HttpExchange exchange, String response) throws Exception {
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** Escape ký tự đặc biệt trong JSON string */
    private static String escapeJson(String text) {
        if (text == null)
            return "";
        return text
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Trích xuất giá trị của một field từ JSON string đơn giản.
     * Dùng cho POST body đơn giản dạng {"ip": "1.2.3.4"}.
     * Không dùng cho JSON lồng nhau phức tạp.
     */
    private static String extractJsonField(String json, String field) {
        if (json == null || json.isEmpty())
            return null;
        // Tìm "field":"value" hoặc "field": "value"
        String search = "\"" + field + "\"";
        int idx = json.indexOf(search);
        if (idx < 0)
            return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0)
            return null;
        // Bỏ qua khoảng trắng
        int start = colon + 1;
        while (start < json.length() && (json.charAt(start) == ' ' || json.charAt(start) == '\t'))
            start++;
        if (start >= json.length())
            return null;
        // Nếu là string (có dấu nháy)
        if (json.charAt(start) == '"') {
            start++;
            int end = json.indexOf('"', start);
            if (end < 0)
                return null;
            return json.substring(start, end);
        }
        // Nếu là value không có nháy (số, boolean)
        int end = start;
        while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}')
            end++;
        return json.substring(start, end).trim();
    }
}