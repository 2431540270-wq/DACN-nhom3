package database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * DatabaseConnection — Manages JDBC connections to MySQL.
 *
 * Usage:
 *   - Call getConnection() to obtain a new Connection object.
 *   - The caller (LogDAO) is responsible for closing the connection when done.
 *
 * Requirements:
 *   - MySQL Server must be running on localhost:3306
 *   - Database "security_logs" must exist (run database/setup.sql)
 *   - mysql-connector-j-x.x.x.jar must be on the Build Path
 */
public class DatabaseConnection {

    // ===== CONNECTION CONFIG =====
    // Adjust these values to match your local environment

    /** MySQL Server URL */
    private static final String URL = "jdbc:mysql://localhost:3306/security_logs"
            + "?useSSL=false"
            + "&allowPublicKeyRetrieval=true"
            + "&serverTimezone=Asia/Ho_Chi_Minh"
            + "&characterEncoding=UTF-8";

    /** MySQL username */
    private static final String USER = "root";

    /**
     * MySQL password.
     * CHANGE THIS to match the password on your machine.
     */
    private static final String PASSWORD = "Phungvanvo358pvv@#";

    /** Tracks whether the connection has been tested (to avoid repeat attempts) */
    private static boolean connectionTested = false;
    private static boolean isAvailable = false;

    /** Throttle DB ping: only re-check every 30 seconds, not on every API call */
    private static long lastPingTime = 0;
    private static final long PING_INTERVAL_MS = 30_000;

    /**
     * Opens and returns a new MySQL connection.
     *
     * A new connection is created on each call.
     * The caller must close it (best done with try-with-resources).
     *
     * @return Connection object
     * @throws SQLException if the connection cannot be established
     */
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    /**
     * Tests the database connection once and caches the result.
     *
     * @return true if MySQL is reachable, false otherwise
     */
    public static boolean testConnection() {
        if (connectionTested) {
            return isAvailable;
        }

        connectionTested = true;

        try {
            // Load the MySQL JDBC driver
            Class.forName("com.mysql.cj.jdbc.Driver");

            // Attempt a connection
            Connection conn = getConnection();
            conn.close();

            isAvailable = true;
            System.out.println("   [Database] MySQL connection successful!");
            System.out.println("   URL: " + URL);

            // Auto-migrate: ensure all required columns exist.
            // Fixes: "Unknown column 'attack_type' in 'field list'" on old databases.
            ensureSchema();

            return true;

        } catch (ClassNotFoundException e) {
            System.err.println("   [Database] MySQL JDBC Driver not found!");
            System.err.println("   -> Download mysql-connector-j from https://dev.mysql.com/downloads/connector/j/");
            System.err.println("   -> Add the .jar file to the Build Path in Eclipse");
            isAvailable = false;
            return false;

        } catch (SQLException e) {
            System.err.println("   [Database] Cannot connect to MySQL!");
            System.err.println("   -> Check that MySQL Server is running");
            System.err.println("   -> Verify username/password in DatabaseConnection.java");
            System.err.println("   -> Error: " + e.getMessage());
            isAvailable = false;
            return false;
        }
    }

    /**
     * Ensures the 'logs' table has all required columns.
     * Runs on every startup after a successful connection.
     *
     * Fixes: "[DB] INSERT error: Unknown column 'attack_type' in 'field list'"
     * which occurs when the table was created before the attack_type column was added.
     *
     * Safe to call multiple times — uses INFORMATION_SCHEMA to skip existing columns.
     */
    private static void ensureSchema() {
        String[][] columnsToAdd = {
            // { column_name, ALTER TABLE SQL }
            { "attack_type",
              "ALTER TABLE logs ADD COLUMN attack_type VARCHAR(50) NOT NULL DEFAULT 'NORMAL' AFTER status" },
            { "description",
              "ALTER TABLE logs ADD COLUMN description TEXT AFTER attack_type" }
        };

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            for (String[] col : columnsToAdd) {
                String colName = col[0];
                String alterSql = col[1];

                // Check if column already exists in INFORMATION_SCHEMA
                String checkSql = "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
                        + "WHERE TABLE_SCHEMA = DATABASE() "
                        + "AND TABLE_NAME = 'logs' "
                        + "AND COLUMN_NAME = '" + colName + "'";

                try (ResultSet rs = stmt.executeQuery(checkSql)) {
                    if (rs.next() && rs.getInt(1) == 0) {
                        // Column missing — add it
                        stmt.executeUpdate(alterSql);
                        System.out.println("   [Schema] Added missing column: " + colName);
                    } else {
                        System.out.println("   [Schema] Column OK: " + colName);
                    }
                }
            }

        } catch (SQLException e) {
            System.err.println("   [Schema] Migration error (non-fatal): " + e.getMessage());
            // Non-fatal: system continues even if migration fails.
            // User can manually run database/migrate.sql to fix.
        }
    }

    /**
     * Returns whether the database is currently reachable.
     *
     * Uses throttled ping: only opens a real connection every PING_INTERVAL_MS (30s).
     * Between pings, returns the cached value to avoid flooding the DB with connections
     * when API endpoints call isAvailable() on every request.
     *
     * [BUG 6 FIX] Nếu testConnection() chưa bao giờ được gọi, tự gọi nó thay vì
     * trả sẵn false mà không thử. Tránh false-negative khi class dùng sai thứ tự.
     */
    public static synchronized boolean isAvailable() {
        // [BUG 6 FIX] Nếu chưa test lần nào → tự khởi tạo
        if (!connectionTested) {
            testConnection();
        }

        // Nếu DB đã được xác nhận không khả dụng → fast fail
        if (!isAvailable) return false;

        long now = System.currentTimeMillis();

        // Within the throttle window — return cached result
        if (now - lastPingTime < PING_INTERVAL_MS) {
            return isAvailable;
        }

        // Throttle window expired — perform a real lightweight ping
        lastPingTime = now;
        try (Connection conn = DriverManager.getConnection(URL, USER, PASSWORD)) {
            isAvailable = conn.isValid(2); // 2-second ping timeout
            return isAvailable;
        } catch (SQLException e) {
            isAvailable = false;
            System.err.println("[Database] Connection lost: " + e.getMessage());
            return false;
        }
    }
}
