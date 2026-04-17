package database;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import model.LogEntry;

/**
 * LogDAO — Data Access Object for the "logs" table in MySQL.
 *
 * Acts as the bridge between Java logic and the database.
 * All SQL queries are centralised here instead of scattered across the
 * codebase.
 *
 * Methods:
 * - insertLog() : Insert a single log entry
 * - insertLogs() : Batch-insert multiple log entries (faster)
 * - getAllLogs() : Retrieve the 100 most recent log entries
 * - getLogsByIP() : Retrieve all logs for a specific IP
 * - getLogCount() : Count total log entries in the database
 * - updateLogs() : Update attack_type and status after SecurityBot analysis
 *
 * All queries use PreparedStatement to prevent SQL injection.
 */
public class LogDAO {

    /**
     * Inserts a single log entry into the database.
     *
     * @param log LogEntry to insert
     * @return true if inserted successfully, false otherwise
     */
    public boolean insertLog(LogEntry log) {

        String sql = "INSERT INTO logs (timestamp, ip_address, action, status, attack_type, score, description) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, log.getTime());
            stmt.setString(2, log.getIp());
            stmt.setString(3, log.getAction());
            stmt.setString(4, log.getStatus());
            stmt.setString(5, log.getAttackType());
            stmt.setInt   (6, log.getScore());
            stmt.setString(7, log.getAction() + " from IP " + log.getIp());

            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                System.out.println("[DB] Saved log: " + log.getIp() + " " + log.getAction());
                return true;
            }

        } catch (SQLException e) {
            System.err.println("[DB] INSERT error: " + e.getMessage());
        }

        return false;
    }

    /**
     * Batch-inserts multiple log entries (significantly faster than inserting one
     * by one).
     *
     * @param logs List of LogEntry to insert
     * @return Number of rows successfully inserted
     */
    public int insertLogs(List<LogEntry> logs) {

        String sql = "INSERT INTO logs (timestamp, ip_address, action, status, attack_type, score, description) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)";

        int count = 0;

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            for (LogEntry log : logs) {
                stmt.setString(1, log.getTime());
                stmt.setString(2, log.getIp());
                stmt.setString(3, log.getAction());
                stmt.setString(4, log.getStatus());
                stmt.setString(5, log.getAttackType());
                stmt.setInt   (6, log.getScore());
                stmt.setString(7, log.getAction() + " from IP " + log.getIp());
                stmt.addBatch();
            }

            int[] results = stmt.executeBatch();
            for (int r : results) {
                if (r >= 0)
                    count++;
            }

            System.out.println("[DB] Batch insert: " + count + "/" + logs.size() + " rows");

        } catch (SQLException e) {
            System.err.println("[DB] Batch INSERT error: " + e.getMessage());
        }

        return count;
    }

    /**
     * Retrieves the 100 most recent log entries from the database.
     *
     * @return List<LogEntry>, or empty list on error
     */
    public List<LogEntry> getAllLogs() {

        List<LogEntry> logs = new ArrayList<>();

        String sql = "SELECT id, timestamp, ip_address, action, status, attack_type, score, description "
                + "FROM logs ORDER BY timestamp DESC LIMIT 100";

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql);
                ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                LogEntry entry = mapResultToLogEntry(rs);
                logs.add(entry);
            }

            System.out.println("[DB] Loaded " + logs.size() + " log row(s) from database");

        } catch (SQLException e) {
            System.err.println("[DB] SELECT error: " + e.getMessage());
        }

        return logs;
    }

    /**
     * Retrieves all log entries for a specific IP address.
     *
     * @param ip IP address to search (e.g. "192.168.1.15")
     * @return List<LogEntry> for that IP
     */
    public List<LogEntry> getLogsByIP(String ip) {

        List<LogEntry> logs = new ArrayList<>();

        String sql = "SELECT id, timestamp, ip_address, action, status, attack_type, score, description "
                + "FROM logs WHERE ip_address = ? ORDER BY timestamp DESC";

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, ip);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    LogEntry entry = mapResultToLogEntry(rs);
                    logs.add(entry);
                }
            }

            System.out.println("[DB] Found " + logs.size() + " log(s) for IP: " + ip);

        } catch (SQLException e) {
            System.err.println("[DB] SELECT by IP error: " + e.getMessage());
        }

        return logs;
    }

    /**
     * Returns the total number of log entries in the database.
     *
     * @return Row count, or 0 on error
     */
    public int getLogCount() {

        String sql = "SELECT COUNT(*) FROM logs";

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql);
                ResultSet rs = stmt.executeQuery()) {

            if (rs.next()) {
                return rs.getInt(1);
            }

        } catch (SQLException e) {
            System.err.println("[DB] COUNT error: " + e.getMessage());
        }

        return 0;
    }

    /**
     * Batch-updates attack_type and status for log entries that have a database ID.
     *
     * Called AFTER SecurityBot.analyze() runs in RAM so that the analysis results
     * (real attack_type, updated status) are persisted back to the database.
     * Without this step, the next call to getAllLogs() would still read stale data.
     *
     * @param logs List of LogEntry already updated by SecurityBot
     * @return Number of rows successfully updated
     */
    public int updateLogs(java.util.List<LogEntry> logs) {

        String sql = "UPDATE logs SET attack_type = ?, status = ?, score = ? WHERE id = ? AND id > 0";

        int count = 0;

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            int batchCount = 0;

            for (LogEntry log : logs) {
                // Only update rows that exist in the DB and have been modified
                if (log.getId() <= 0 || !log.isModified())
                    continue;

                stmt.setString(1, log.getAttackType());
                stmt.setString(2, log.getStatus());
                stmt.setInt   (3, log.getScore());
                stmt.setInt   (4, log.getId());
                stmt.addBatch();
                batchCount++;
            }

            // Only execute if there is at least one entry — avoids empty-batch exception
            if (batchCount > 0) {
                int[] results = stmt.executeBatch();
                for (int r : results) {
                    if (r >= 0)
                        count++;
                }
                System.out.println("[DB] updateLogs: updated " + count + " row(s)");
            }

        } catch (SQLException e) {
            System.err.println("[DB] updateLogs error: " + e.getMessage());
        }

        return count;
    }

    /**
     * Retrieves all unique IPs that have a BLOCKED status in the database.
     * This is used to re-populate the Firewall on server startup.
     *
     * @return List of blocked IP addresses
     */
    public List<String> getBlockedIPs() {
        List<String> blockedIPs = new ArrayList<>();
        String sql = "SELECT DISTINCT ip_address FROM logs WHERE status = 'BLOCKED'";

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql);
                ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                blockedIPs.add(rs.getString("ip_address"));
            }
            if (!blockedIPs.isEmpty()) {
                System.out.println("[DB] Loaded " + blockedIPs.size() + " BLOCKED IP(s) from database into Firewall");
            }

        } catch (SQLException e) {
            System.err.println("[DB] getBlockedIPs error: " + e.getMessage());
        }

        return blockedIPs;
    }

    /**
     * Maps a single ResultSet row to a LogEntry object.
     * Extracted to avoid duplicated mapping code in getAllLogs() and getLogsByIP().
     */
    private LogEntry mapResultToLogEntry(ResultSet rs) throws SQLException {

        String time = rs.getString("timestamp");
        String ip = rs.getString("ip_address");
        String action = rs.getString("action");
        String attackType = rs.getString("attack_type");

        LogEntry entry = new LogEntry(time, ip, action);
        if (attackType == null || attackType.isEmpty()) {
            attackType = "NORMAL";
        }
        entry.setAttackType(attackType);
        entry.setStatus(rs.getString("status"));

        // Đọc score THỰC từ DB (do SecurityBot tính và persist qua updateLogs).
        // Nếu score=0 (row cũ trước migration), fallback về calculateScoreFromStatus.
        int dbScore = rs.getInt("score");
        entry.setScore(dbScore > 0 ? dbScore : calculateScoreFromStatus(rs.getString("status")));

        entry.setId(rs.getInt("id"));
        entry.setDescription(rs.getString("description"));

        // Reset isModified: các setters đánh dấu entry là "đã sửa" ngay khi đọc từ DB.
        // Nếu không reset, updateLogs() sẽ ghi lại TẤT CẢ 100 log mỗi 2 giây.
        // Sau reset, chỉ những log mà SecurityBot thực sự thay đổi mới được persist.
        entry.resetModified();

        return entry;
    }

    /**
     * Derives a numeric risk score from the status string.
     * Used to populate the score field when reading from the database
     * (the database does not store a score column).
     */
    private int calculateScoreFromStatus(String status) {
        if (status == null)
            return 0;
        switch (status) {
            case "BLOCKED":
                return 90;
            case "MONITORING":
                return 60;
            case "SUSPICIOUS":
                return 30;
            case "PASS":
                return 5;
            default:
                return 0;
        }
    }

    /**
     * Xóa toàn bộ dữ liệu của IP vừa được admin gỡ block — IP trở về "trong sạch".
     *
     * Thực hiện 2 bước:
     * 1. DELETE tất cả log (bảng logs) của IP này.
     * → failMap[ip] = 0 và requestMap[ip] = 0 → analyze() không có dữ liệu để
     * re-block.
     * → IP bắt đầu lại từ đầu, không bị cộng dồn điểm từ lịch sử cũ.
     * 2. DELETE tất cả cảnh báo (bảng alerts) của IP này.
     * → Trang Alerts sẽ không còn hiển thị cảnh báo cũ cho IP vừa được tha.
     * → Đảm bảo tính nhất quán: không có log → không có alert là đúng.
     *
     * @param ip IP address cần dọn sạch trong DB
     * @return Tổng số rows đã xóa (logs + alerts)
     */
    public int unblockInDB(String ip) {
        int total = 0;

        // Bước 1: Xóa toàn bộ log của IP khỏi bảng logs
        // failMap[ip] = 0, requestMap[ip] = 0 → riskScore = 0 → không re-block
        String deleteLogsSql = "DELETE FROM logs WHERE ip_address = ?";
        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(deleteLogsSql)) {
            stmt.setString(1, ip);
            int deleted = stmt.executeUpdate();
            System.out.println("[DB] unblockInDB: Deleted " + deleted + " log(s) for IP: " + ip);
            total += deleted;
        } catch (SQLException e) {
            System.err.println("[DB] unblockInDB DELETE logs error: " + e.getMessage());
        }

        // Bước 2: Xóa toàn bộ cảnh báo của IP khỏi bảng alerts
        // Trang Alerts sẽ sạch – không còn cảnh báo cũ cho IP vừa được gỡ block
        String deleteAlertsSql = "DELETE FROM alerts WHERE ip_address = ?";
        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(deleteAlertsSql)) {
            stmt.setString(1, ip);
            int deleted = stmt.executeUpdate();
            System.out.println("[DB] unblockInDB: Deleted " + deleted + " alert(s) for IP: " + ip);
            total += deleted;
        } catch (SQLException e) {
            System.err.println("[DB] unblockInDB DELETE alerts error: " + e.getMessage());
        }

        return total;
    }

    /**
     * Retrieves the most recent 200 alert records from the alerts table.
     *
     * Used by /api/alerts endpoint as the primary data source (replaces the
     * in-memory AlertSystem list so that alerts persist across restarts).
     *
     * @return List of Maps with keys: time, level, attack, ip, score
     */
    public List<java.util.Map<String, Object>> getAlertsFromDB() {
        List<java.util.Map<String, Object>> result = new ArrayList<>();

        String sql = "SELECT ip_address, attack_type, risk_score, alert_level, created_at "
                + "FROM alerts ORDER BY created_at DESC LIMIT 200";

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql);
                ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                java.util.Map<String, Object> alert = new java.util.LinkedHashMap<>();
                alert.put("time", rs.getString("created_at"));
                alert.put("level", rs.getString("alert_level"));
                alert.put("attack", rs.getString("attack_type"));
                alert.put("ip", rs.getString("ip_address"));
                alert.put("score", rs.getInt("risk_score"));
                result.add(alert);
            }

            System.out.println("[DB] getAlertsFromDB: Loaded " + result.size() + " alert(s)");

        } catch (SQLException e) {
            System.err.println("[DB] getAlertsFromDB error: " + e.getMessage());
        }

        return result;
    }
}
