package database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * DatabaseConnection — Quản lý kết nối đến MySQL Database.
 *
 * Cách hoạt động:
 * - Dùng JDBC (Java Database Connectivity) để kết nối MySQL
 * - Gọi getConnection() để lấy 1 Connection object
 * - Connection này sau đó được LogDAO dùng để chạy SQL query
 *
 * Yêu cầu:
 * - MySQL Server phải đang chạy trên localhost:3306
 * - Database "security_logs" phải đã được tạo (chạy setup.sql)
 * - File mysql-connector-j-x.x.x.jar phải nằm trong Build Path
 */
public class DatabaseConnection {

    // ===== CẤU HÌNH KẾT NỐI =====
    // Sửa các giá trị này cho phù hợp với máy của bạn

    /** Địa chỉ MySQL Server (mặc định localhost, port 3306) */
    private static final String URL = "jdbc:mysql://localhost:3306/security_logs"
            + "?useSSL=false" // Tắt SSL (dev local không cần)
            + "&allowPublicKeyRetrieval=true" // Cho phép lấy public key
            + "&serverTimezone=Asia/Ho_Chi_Minh" // Múi giờ Việt Nam
            + "&characterEncoding=UTF-8"; // Hỗ trợ tiếng Việt

    /** Tên đăng nhập MySQL (mặc định là root) */
    private static final String USER = "root";

    /**
     * Mật khẩu MySQL.
     * THAY ĐỔI GIÁ TRỊ NÀY cho đúng mật khẩu MySQL trên máy bạn!
     * Ví dụ: "" (rỗng), "1234", "password"...
     */
    private static final String PASSWORD = "Phungvanvo358pvv@#";

    /** Biến theo dõi trạng thái kết nối (để tránh in log lặp) */
    private static boolean connectionTested = false;
    private static boolean isAvailable = false;

    /**
     * Lấy một Connection mới đến MySQL Database.
     *
     * Mỗi lần gọi sẽ tạo 1 connection mới.
     * Caller (LogDAO) có trách nhiệm đóng connection sau khi dùng xong.
     *
     * @return Connection object nếu thành công
     * @throws SQLException nếu không kết nối được
     */
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    /**
     * Kiểm tra xem Database có khả dụng không.
     * Thử kết nối 1 lần, ghi nhớ kết quả.
     *
     * @return true nếu kết nối MySQL thành công
     */
    public static boolean testConnection() {
        if (connectionTested) {
            return isAvailable;
        }

        connectionTested = true;

        try {
            // Nạp MySQL JDBC Driver vào bộ nhớ
            Class.forName("com.mysql.cj.jdbc.Driver");

            // Thử kết nối
            Connection conn = getConnection();
            conn.close();

            isAvailable = true;
            System.out.println("   [Database] Kết nối MySQL thành công!");
            System.out.println("   URL: " + URL);
            return true;

        } catch (ClassNotFoundException e) {
            System.err.println("   [Database] Thiếu MySQL JDBC Driver!");
            System.err.println("   → Tải mysql-connector-j từ https://dev.mysql.com/downloads/connector/j/");
            System.err.println("   → Thêm file .jar vào Build Path trong Eclipse");
            isAvailable = false;
            return false;

        } catch (SQLException e) {
            System.err.println("   [Database] Không kết nối được MySQL!");
            System.err.println("   → Kiểm tra MySQL Server có đang chạy không");
            System.err.println("   → Kiểm tra username/password trong DatabaseConnection.java");
            System.err.println("   → Lỗi: " + e.getMessage());
            isAvailable = false;
            return false;
        }
    }

    /**
     * Kiểm tra nhanh database có khả dụng không (không thử lại).
     */
    public static boolean isAvailable() {
        return isAvailable;
    }
}
