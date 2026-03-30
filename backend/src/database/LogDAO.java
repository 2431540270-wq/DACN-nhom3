package database;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import model.LogEntry;

/**
 * LogDAO — Data Access Object for the "logs" table in MySQL.
 *
 * Acts as the bridge between Java logic and the database.
 * All SQL queries are centralised here instead of scattered across the codebase.
 *
 * Methods:
 *   - insertLog()   : Insert a single log entry
 *   - insertLogs()  : Batch-insert multiple log entries (faster)
 *   - getAllLogs()   : Retrieve the 100 most recent log entries
 *   - getLogsByIP() : Retrieve all logs for a specific IP
 *   - getLogCount() : Count total log entries in the database
 *   - updateLogs()  : Update attack_type and status after SecurityBot analysis
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

        String sql = "INSERT INTO logs (timestamp, ip_address, action, status, attack_type, description) "
                + "VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, log.getTime());
            stmt.setString(2, log.getIp());
            stmt.setString(3, log.getAction());
            stmt.setString(4, log.getStatus());
            stmt.setString(5, log.getAttackType());
            stmt.setString(6, log.getAction() + " from IP " + log.getIp());

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
     * Batch-inserts multiple log entries (significantly faster than inserting one by one).
     *
     * @param logs List of LogEntry to insert
     * @return Number of rows successfully inserted
     */
    public int insertLogs(List<LogEntry> logs) {

        String sql = "INSERT INTO logs (timestamp, ip_address, action, status, attack_type, description) "
                + "VALUES (?, ?, ?, ?, ?, ?)";

        int count = 0;

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            for (LogEntry log : logs) {
                stmt.setString(1, log.getTime());
                stmt.setString(2, log.getIp());
                stmt.setString(3, log.getAction());
                stmt.setString(4, log.getStatus());
                stmt.setString(5, log.getAttackType());
                stmt.setString(6, log.getAction() + " from IP " + log.getIp());
                stmt.addBatch();
            }

            int[] results = stmt.executeBatch();
            for (int r : results) {
                if (r >= 0) count++;
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

        String sql = "SELECT id, timestamp, ip_address, action, status, attack_type, description "
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

        String sql = "SELECT id, timestamp, ip_address, action, status, attack_type, description "
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

        String sql = "UPDATE logs SET attack_type = ?, status = ? WHERE id = ? AND id > 0";

        int count = 0;

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            int batchCount = 0;

            for (LogEntry log : logs) {
                // Only update rows that exist in the DB (id > 0)
                if (log.getId() <= 0) continue;

                stmt.setString(1, log.getAttackType());
                stmt.setString(2, log.getStatus());
                stmt.setInt(3, log.getId());
                stmt.addBatch();
                batchCount++;
            }

            // Only execute if there is at least one entry — avoids empty-batch exception
            if (batchCount > 0) {
                int[] results = stmt.executeBatch();
                for (int r : results) {
                    if (r >= 0) count++;
                }
                System.out.println("[DB] updateLogs: updated " + count + " row(s)");
            }

        } catch (SQLException e) {
            System.err.println("[DB] updateLogs error: " + e.getMessage());
        }

        return count;
    }

    /**
     * Maps a single ResultSet row to a LogEntry object.
     * Extracted to avoid duplicated mapping code in getAllLogs() and getLogsByIP().
     */
    private LogEntry mapResultToLogEntry(ResultSet rs) throws SQLException {

        String time      = rs.getString("timestamp");
        String ip        = rs.getString("ip_address");
        String action    = rs.getString("action");
        String attackType = rs.getString("attack_type");

        LogEntry entry = new LogEntry(time, ip, action);
        if (attackType == null || attackType.isEmpty()) {
            attackType = "NORMAL";
        }
        entry.setAttackType(attackType);
        entry.setStatus(rs.getString("status"));
        entry.setScore(calculateScoreFromStatus(rs.getString("status")));
        entry.setId(rs.getInt("id"));
        entry.setDescription(rs.getString("description"));

        return entry;
    }

    /**
     * Derives a numeric risk score from the status string.
     * Used to populate the score field when reading from the database
     * (the database does not store a score column).
     */
    private int calculateScoreFromStatus(String status) {
        if (status == null) return 0;
        switch (status) {
            case "BLOCKED":    return 90;
            case "MONITORING": return 60;
            case "SUSPICIOUS": return 30;
            case "PASS":       return 5;
            default:           return 0;
        }
    }
}
