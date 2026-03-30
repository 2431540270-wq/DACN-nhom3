package database;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import model.LogEntry;

/**
 * LogDAO — Data Access Object để thao tác với bảng "logs" trong MySQL.
 *
 * DAO là tầng trung gian giữa Code Java và Database.
 * Thay vì viết SQL rải rác khắp nơi, tất cả query đều nằm ở đây.
 *
 * Các method:
 * - insertLog() : Chèn 1 dòng log mới vào database
 * - getAllLogs() : Lấy 100 dòng log mới nhất
 * - getLogsByIP() : Tìm log theo địa chỉ IP
 * - getLogCount() : Đếm tổng số log trong database
 *
 * Tất cả đều dùng PreparedStatement (chống SQL Injection).
 */
public class LogDAO {

    /**
     * Chèn 1 dòng log mới vào database.
     *
     * @param log LogEntry chứa thông tin log
     * @return true nếu chèn thành công, false nếu thất bại
     */
    public boolean insertLog(LogEntry log) {

        String sql = "INSERT INTO logs (timestamp, ip_address, action, status, attack_type, description) "
                + "VALUES (?, ?, ?, ?, ?, ?)";

        // try-with-resources: tự đóng Connection + PreparedStatement khi xong
        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            // Gán giá trị vào các dấu ? (vị trí 1, 2, 3...)
            // PreparedStatement tự escape ký tự đặc biệt → chống SQL Injection
            stmt.setString(1, log.getTime());
            stmt.setString(2, log.getIp());
            stmt.setString(3, log.getAction());
            stmt.setString(4, log.getStatus());
            stmt.setString(5, log.getAttackType());
            stmt.setString(6, log.getAction() + " từ IP " + log.getIp());

            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                System.out.println("[DB] Đã lưu log: " + log.getIp() + " " + log.getAction());
                return true;
            }

        } catch (SQLException e) {
            System.err.println("[DB] Lỗi INSERT log: " + e.getMessage());
        }

        return false;
    }

    /**
     * Chèn nhiều log cùng lúc (batch insert — nhanh hơn insert từng dòng).
     *
     * @param logs Danh sách LogEntry cần lưu
     * @return Số dòng đã chèn thành công
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
                stmt.setString(6, log.getAction() + " từ IP " + log.getIp());
                stmt.addBatch(); // Thêm vào hàng đợi batch
            }

            int[] results = stmt.executeBatch(); // Chạy tất cả 1 lần
            for (int r : results) {
                if (r >= 0)
                    count++;
            }

            System.out.println("[DB] Batch insert: " + count + "/" + logs.size() + " dòng");

        } catch (SQLException e) {
            System.err.println("[DB] Lỗi batch INSERT: " + e.getMessage());
        }

        return count;
    }

    /**
     * Lấy 100 dòng log mới nhất từ database.
     *
     * @return List<LogEntry> danh sách log, hoặc list rỗng nếu lỗi
     */
    public List<LogEntry> getAllLogs() {

        List<LogEntry> logs = new ArrayList<>();

        String sql = "SELECT id, timestamp, ip_address, action, status, attack_type, description "
                + "FROM logs ORDER BY timestamp DESC LIMIT 100";

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql);
                ResultSet rs = stmt.executeQuery()) {

            // Duyệt từng dòng kết quả (rs.next() trả false khi hết dòng)
            while (rs.next()) {
                LogEntry entry = mapResultToLogEntry(rs);
                logs.add(entry);
            }

            System.out.println("[DB] Đọc được " + logs.size() + " dòng log từ database");

        } catch (SQLException e) {
            System.err.println("[DB] Lỗi SELECT logs: " + e.getMessage());
        }

        return logs;
    }

    /**
     * Tìm log theo địa chỉ IP.
     *
     * @param ip Địa chỉ IP cần tìm (VD: "192.168.1.15")
     * @return List<LogEntry> danh sách log của IP đó
     */
    public List<LogEntry> getLogsByIP(String ip) {

        List<LogEntry> logs = new ArrayList<>();

        String sql = "SELECT id, timestamp, ip_address, action, status, attack_type, description "
                + "FROM logs WHERE ip_address = ? ORDER BY timestamp DESC";

        try (Connection conn = DatabaseConnection.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, ip); // Gán IP vào dấu ?

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    LogEntry entry = mapResultToLogEntry(rs);
                    logs.add(entry);
                }
            }

            System.out.println("[DB] Tìm thấy " + logs.size() + " log cho IP: " + ip);

        } catch (SQLException e) {
            System.err.println("[DB] Lỗi SELECT by IP: " + e.getMessage());
        }

        return logs;
    }

    /**
     * Đếm tổng số log trong database.
     *
     * @return Số lượng dòng log, hoặc 0 nếu lỗi
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
            System.err.println("[DB] Lỗi COUNT: " + e.getMessage());
        }

        return 0;
    }

    /**
     * Hàm phụ: Chuyển 1 dòng ResultSet thành LogEntry object.
     * Tách riêng để tránh lặp code trong getAllLogs() và getLogsByIP().
     */
    private LogEntry mapResultToLogEntry(ResultSet rs) throws SQLException {

        String time = rs.getString("timestamp");
        String ip = rs.getString("ip_address");
        String action = rs.getString("action");
        String attackType = rs.getString("attack_type");

        // Tạo LogEntry bằng constructor cũ (3 tham số)
        LogEntry entry = new LogEntry(time, ip, action);
        if (attackType == null || attackType.isEmpty()) {
            attackType = "NORMAL";
        }
        entry.setAttackType(attackType);
        // Gán thêm các field từ database
        entry.setStatus(rs.getString("status"));
        entry.setScore(calculateScoreFromStatus(rs.getString("status")));

        // Gán id và description từ DB
        entry.setId(rs.getInt("id"));
        entry.setDescription(rs.getString("description"));

        return entry;
    }

    /**
     * Hàm phụ: Tính score từ status (vì database không có cột score).
     * Dùng để hiển thị score trên Frontend.
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
}
