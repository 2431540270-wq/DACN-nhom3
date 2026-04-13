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
 * ApiServer — HTTP API server that serves data to the frontend.
 *
 * Port: 8080 (http://localhost:8080)
 *
 * Data source priority:
 * 1. MySQL Database (via LogDAO) — preferred
 * 2. Text file (via LogReader) — fallback if DB is unavailable
 *
 * Endpoints:
 * GET /api/analyze — Analyze logs, compute risk scores
 * GET /api/logs — Retrieve the 100 most recent log entries
 * GET /api/alerts — Retrieve the current alert list
 * GET /api/blocked — Retrieve the list of blocked IPs
 * POST /api/block — Manually block an IP
 * POST /api/unblock — Manually unblock an IP
 */
public class ApiServer {

    private static List<LogEntry> logs = new ArrayList<>();
    private static AlertSystem alertSystem;
    private static SecurityBot bot;
    private static LogDAO logDAO = new LogDAO();
    // NOTE: LogGenerator is started once from Main.java.
    // Do NOT instantiate it here — doing so causes duplicate DB inserts.

    /**
     * Starts the HTTP API server.
     *
     * @param sharedBot         Shared SecurityBot instance
     * @param sharedAlertSystem Shared AlertSystem instance
     */
    public static void startServer(SecurityBot sharedBot, AlertSystem sharedAlertSystem) throws Exception {

        bot = sharedBot;
        alertSystem = sharedAlertSystem;

        // Load persistency: Blocked IPs from DB to restore memory Firewall state
        if (DatabaseConnection.isAvailable()) {
            List<String> blockedIPs = logDAO.getBlockedIPs();
            for (String ip : blockedIPs) {
                bot.getFirewall().blockIP(ip);
            }
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        // ============================================================
        // ENDPOINT 1: GET /api/analyze
        // ============================================================
        server.createContext("/api/analyze", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                // Read latest logs from DB / file — do NOT call bot.analyze() here.
                // RealTimeMonitor already runs analyze() every 2s in its own thread.
                // Calling analyze() here again would cause dangerHistory to double-accumulate.
                if (DatabaseConnection.isAvailable()) {
                    logs = logDAO.getAllLogs();
                    System.out.println("[API /analyze] Source: DATABASE — " + logs.size() + " row(s)");
                } else {
                    // Fallback: read from text file
                    LogReader reader = new LogReader();
                    logs = reader.readLog("logs/network.log");
                    if (logs == null)
                        logs = new ArrayList<>();
                    System.out.println("[API /analyze] Source: FILE — " + logs.size() + " row(s)");
                }

                // Use DB total count for the response (more accurate than logs.size())
                int displayTotal = logs.size();
                double riskAvg = 0;

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
                    riskAvg = Math.round((double) totalRisk / logs.size() * 10.0) / 10.0;
                }

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
        // ENDPOINT 2: GET /api/logs
        // ============================================================
        server.createContext("/api/logs", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                // Prefer database; fall back to the last in-memory list
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

                System.out.println("[API /logs] Returning " + limit + " row(s)");
                sendJson(exchange, json.toString());

            } catch (Exception e) {
                System.err.println("[API /logs] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // ============================================================
        // ENDPOINT 3: GET /api/alerts
        // ============================================================
        server.createContext("/api/alerts", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                StringBuilder json = new StringBuilder("[");

                if (DatabaseConnection.isAvailable()) {
                    // PRIMARY: Read structured data directly from the alerts table in DB.
                    // This is cleaner than parsing raw strings from the in-memory list.
                    List<java.util.Map<String, Object>> dbAlerts = logDAO.getAlertsFromDB();
                    System.out.println("[API /alerts] " + dbAlerts.size() + " alert(s) from DB");

                    for (int i = 0; i < dbAlerts.size(); i++) {
                        java.util.Map<String, Object> a = dbAlerts.get(i);
                        json.append("{")
                                .append("\"time\":\"").append(escapeJson(String.valueOf(a.get("time")))).append("\",")
                                .append("\"level\":\"").append(escapeJson(String.valueOf(a.get("level")))).append("\",")
                                .append("\"attack\":\"").append(escapeJson(String.valueOf(a.get("attack")))).append("\",")
                                .append("\"ip\":\"").append(escapeJson(String.valueOf(a.get("ip")))).append("\",")
                                .append("\"score\":").append(a.get("score"))
                                .append("}");
                        if (i < dbAlerts.size() - 1)
                            json.append(",");
                    }

                } else {
                    // FALLBACK: Parse the in-memory alert strings when DB is unavailable.
                    List<String> alerts = alertSystem.getAlerts();
                    System.out.println("[API /alerts] " + alerts.size() + " alert(s) from memory (DB unavailable)");

                    for (int i = 0; i < alerts.size(); i++) {
                        String alert = alerts.get(i);

                        String level = "LOW";
                        String attack = "UNKNOWN";
                        String ip = "0.0.0.0";
                        int score = 10;

                        if (alert.contains("🚨")) { level = "CRITICAL"; score = 90; }
                        else if (alert.contains("🔴")) { level = "HIGH"; score = 70; }
                        else if (alert.contains("⚠")) { level = "MEDIUM"; score = 50; }

                        if (alert.contains("BRUTE_FORCE")) attack = "BRUTE_FORCE";
                        else if (alert.contains("REQUEST_FLOOD")) attack = "REQUEST_FLOOD";
                        else if (level.equals("CRITICAL")) attack = "BRUTE_FORCE";
                        else if (level.equals("HIGH")) attack = "REQUEST_FLOOD";
                        else attack = "DANGEROUS_ACTIVITY";

                        for (String p : alert.split(" ")) {
                            if (p.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) { ip = p; }
                        }

                        String time = "";
                        if (alert.contains("]")) {
                            int s = alert.indexOf("["), e = alert.indexOf("]");
                            if (s >= 0 && e > s) time = alert.substring(s + 1, e);
                        }

                        json.append("{")
                                .append("\"time\":\"").append(escapeJson(time)).append("\",")
                                .append("\"level\":\"").append(escapeJson(level)).append("\",")
                                .append("\"attack\":\"").append(escapeJson(attack)).append("\",")
                                .append("\"ip\":\"").append(escapeJson(ip)).append("\",")
                                .append("\"score\":").append(score)
                                .append("}");
                        if (i < alerts.size() - 1) json.append(",");
                    }
                }

                json.append("]");
                sendJson(exchange, json.toString());

            } catch (Exception e) {
                System.err.println("[API /alerts] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // ============================================================
        // ENDPOINT 4: GET /api/blocked
        // ============================================================
        server.createContext("/api/blocked", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                // Use a snapshot to avoid ConcurrentModificationException
                // if Firewall.blockIP() is called from another thread during iteration
                Set<String> ipsSnapshot = new java.util.HashSet<>(bot.getFirewall().getBlockedIPs());
                System.out.println("[API /blocked] " + ipsSnapshot.size() + " blocked IP(s)");

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
        // ENDPOINT 5: POST /api/block — Manually block an IP
        // ============================================================
        server.createContext("/api/block", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                // Read POST body: { "ip": "192.168.1.1" }
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String ip = extractJsonField(body, "ip");

                if (ip == null || ip.isEmpty() || !ip.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
                    byte[] err = "{\"success\":false,\"message\":\"Invalid IP address\"}"
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(400, err.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(err);
                    }
                    return;
                }

                bot.getFirewall().blockIP(ip);
                System.out.println("[API /block] Manually blocked IP: " + ip);
                sendJson(exchange, "{\"success\":true,\"message\":\"Blocked IP " + escapeJson(ip) + "\"}");

            } catch (Exception e) {
                System.err.println("[API /block] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // ============================================================
        // ENDPOINT 6: POST /api/unblock — Manually unblock an IP
        // ============================================================
        server.createContext("/api/unblock", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String ip = extractJsonField(body, "ip");

                if (ip == null || ip.isEmpty()) {
                    byte[] err = "{\"success\":false,\"message\":\"Invalid IP address\"}"
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(400, err.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(err);
                    }
                    return;
                }

                bot.getFirewall().unblockIP(ip);

                // [BUG 8 FIX] Persist vào DB để tránh re-block sau khi restart
                if (DatabaseConnection.isAvailable()) {
                    logDAO.unblockInDB(ip);
                }

                System.out.println("[API /unblock] Unblocked IP: " + ip);
                sendJson(exchange, "{\"success\":true,\"message\":\"Unblocked IP " + escapeJson(ip) + "\"}");

            } catch (Exception e) {
                System.err.println("[API /unblock] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        });

        // ============================================================
        // ENDPOINT 7: POST /api/attack/bruteforce [BUG 2 FIX — Red Team]
        // ============================================================
        server.createContext("/api/attack/bruteforce", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                // Lấy IP của máy gọi (Red Team client)
                String attackerIP = exchange.getRemoteAddress().getAddress().getHostAddress();

                // Nếu IP đã bị block → trả 403
                if (bot.getFirewall().isBlocked(attackerIP)) {
                    byte[] err = "{\"blocked\":true,\"message\":\"Your IP is blocked\"}"
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(403, err.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(err);
                    }
                    System.out.println("[API /attack/bruteforce] BLOCKED IP tried: " + attackerIP);
                    return;
                }

                // Ghi 1 log LOGIN_FAIL vào DB
                if (DatabaseConnection.isAvailable()) {
                    String time = java.time.LocalDateTime.now()
                            .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                    model.LogEntry attackLog = new model.LogEntry(time, attackerIP, "LOGIN_FAIL");
                    attackLog.setStatus("SUSPICIOUS");
                    attackLog.setAttackType("BRUTE_FORCE");
                    logDAO.insertLog(attackLog);
                }

                System.out.println("[API /attack/bruteforce] LOGIN_FAIL from: " + attackerIP);
                sendJson(exchange,
                        "{\"success\":true,\"action\":\"LOGIN_FAIL\",\"ip\":\"" + escapeJson(attackerIP) + "\"}");

            } catch (Exception e) {
                System.err.println("[API /attack/bruteforce] ERROR: " + e.getMessage());
            }
        });

        // ============================================================
        // ENDPOINT 8: POST /api/attack/flood [BUG 2 FIX — Red Team]
        // ============================================================
        server.createContext("/api/attack/flood", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                String attackerIP = exchange.getRemoteAddress().getAddress().getHostAddress();

                if (bot.getFirewall().isBlocked(attackerIP)) {
                    byte[] err = "{\"blocked\":true,\"message\":\"Your IP is blocked\"}"
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(403, err.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(err);
                    }
                    System.out.println("[API /attack/flood] BLOCKED IP tried: " + attackerIP);
                    return;
                }

                // Ghi 1 log REQUEST vào DB
                if (DatabaseConnection.isAvailable()) {
                    String time = java.time.LocalDateTime.now()
                            .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                    model.LogEntry attackLog = new model.LogEntry(time, attackerIP, "REQUEST");
                    attackLog.setStatus("PASS");
                    attackLog.setAttackType("REQUEST_FLOOD");
                    logDAO.insertLog(attackLog);
                }

                System.out.println("[API /attack/flood] REQUEST from: " + attackerIP);
                sendJson(exchange,
                        "{\"success\":true,\"action\":\"REQUEST\",\"ip\":\"" + escapeJson(attackerIP) + "\"}");

            } catch (Exception e) {
                System.err.println("[API /attack/flood] ERROR: " + e.getMessage());
            }
        });

        // ============================================================
        // ENDPOINT 9: GET /api/check-block [BUG 2 FIX — Red Team]
        // ============================================================
        server.createContext("/api/check-block", (HttpExchange exchange) -> {
            try {
                if (handleCors(exchange))
                    return;

                String callerIP = exchange.getRemoteAddress().getAddress().getHostAddress();
                boolean isBlocked = bot.getFirewall().isBlocked(callerIP);

                System.out.println("[API /check-block] IP: " + callerIP + " blocked=" + isBlocked);
                sendJson(exchange, "{\"blocked\":" + isBlocked + ",\"ip\":\"" + escapeJson(callerIP) + "\"}");

            } catch (Exception e) {
                System.err.println("[API /check-block] ERROR: " + e.getMessage());
            }
        });

        server.start();
        System.out.println("   API Server running at http://192.168.1.8:8080");
        System.out
                .println("   Blue Team: /api/analyze, /api/logs, /api/alerts, /api/blocked, /api/block, /api/unblock");
        System.out.println("   Red Team:  /api/attack/bruteforce, /api/attack/flood, /api/check-block");
        System.out.println(
                "   Data source: " + (DatabaseConnection.isAvailable() ? "MySQL Database" : "File text (fallback)"));
    }

    // ============================================================
    // HELPER METHODS
    // ============================================================

    /** Sets CORS headers and handles OPTIONS preflight requests. */
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

    /** Sends a JSON string as an HTTP 200 response with UTF-8 encoding. */
    private static void sendJson(HttpExchange exchange, String response) throws Exception {
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** Escapes special characters in a JSON string value. */
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
     * Extracts a field value from a simple flat JSON string.
     * Intended for POST bodies like {"ip": "1.2.3.4"}.
     * Not suitable for nested JSON structures.
     */
    private static String extractJsonField(String json, String field) {
        if (json == null || json.isEmpty())
            return null;

        String search = "\"" + field + "\"";
        int idx = json.indexOf(search);
        if (idx < 0)
            return null;

        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0)
            return null;

        // Skip whitespace after the colon
        int start = colon + 1;
        while (start < json.length() && (json.charAt(start) == ' ' || json.charAt(start) == '\t'))
            start++;
        if (start >= json.length())
            return null;

        // String value (quoted)
        if (json.charAt(start) == '"') {
            start++;
            int end = json.indexOf('"', start);
            if (end < 0)
                return null;
            return json.substring(start, end);
        }

        // Non-string value (number, boolean)
        int end = start;
        while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}')
            end++;
        return json.substring(start, end).trim();
    }
}