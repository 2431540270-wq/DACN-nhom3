package alert;

import java.io.*;
import java.util.*;

/**
 * LỚP: AlertSystem (Hệ Thống Chuông Báo Động)
 * 
 * Mục đích:
 * Nơi này làm nhiệm vụ GHI CHÉP (lưu vào file txt) và
 * HUÝT CÒI (lưu vào danh sách Array) khi Bot phát hiện IP cờ-hó.
 * Những lời cảnh báo này sau đó sẽ được rải lên Frontend HTML.
 */
public class AlertSystem {

    /**
     * TỪ KHÓA MỚI: "Collections.synchronizedList"
     * Tại sao lại có từ này? Vì trong môi trường Thực tế, ApiServer gọi hàm đọc dữ
     * liệu
     * CÙNG LÚC với RealTimeMonitor đang ghi đè List Alerts mới.
     * Rắc rối xảy ra y hệt 2 người cùng tranh nhau giành cái ghế -> Văng Lỗi
     * "ConcurrentModification" chói rọi (Gãy máy).
     * Do đó, Sync List biến cái Array báo động này thành 1 cái PHÒNG KHOA CỬA CÓ
     * TÍNH NẮM. Vào thì phải Xếp hàng mới Không Lỗi!
     */
    private List<String> alerts = Collections.synchronizedList(new ArrayList<>());

    // Nơi cất giấu cái file báo cáo ghi chép
    private final String ALERT_FILE = "alerts/alert.txt";

    /**
     * HÀM NẠP ĐẦU TIÊN (CONSTRUCTOR): Khởi động là Đọc File text thô lên luôn.
     */
    public AlertSystem() {
        loadAlertsFromFile();
    }

    /**
     * HÀM XU HƯỚNG: Thêm cảnh báo mới vào loa phường.
     */
    public void addAlert(String message) {

        // Gắn tem ngày tháng (để Front end biết cảnh báo nãy nhảy giờ nào)
        String timeStampedMessage = "[" + new Date().toString() + "] " + message;

        // Thêm vào "Bộ nhớ Tạm RAM"
        alerts.add(timeStampedMessage);

        // Xuất luôn ra Ổ CỨNG máy tính
        saveAlertToFile(timeStampedMessage);

        System.out.println(timeStampedMessage); // In luôn lên Màn hình cmd Backend Console cho Admin dòm thấy.
    }

    /**
     * Lấy toàn bộ các phong bì thư (cảnh báo)
     * Tại sao trả ra Bản Sao "new ArrayList"? Để Tránh tình trạng Thằng đang đọc
     * thì thằng khác lao qua đá đổ.
     */
    public List<String> getAlerts() {
        return new ArrayList<>(alerts);
    }

    /**
     * Cú Clear: Dọn sạch mọi vết tích cũ (phát loa mệt rồi).
     */
    public void clearAlerts() {
        alerts.clear();
    }

    /**
     * HÀM GHI FILE: ("FileWriter" là bút bi, "BufferedWriter" là cái giấy than tốc
     * độ cao).
     * "true" nghĩa là viết nối tiếp, cấm xóa file để viết lại từ đầu.
     */
    private void saveAlertToFile(String message) {
        // Cú pháp đặc quyền Try-With-Resources (nằm thoi lỏi giữa cặp ngoặc đơn tròn (
        // ) )
        // Mẹo Auto-Close Tự Động Rán Nắp Ngay Khi Ráng Lỗi Tránh File bị Kẹt ở máy khi
        // văng ngoại lệ.
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(ALERT_FILE, true))) {
            writer.write(message);
            writer.newLine(); // Xuống dòng mới "\n"
        } catch (IOException e) {
            System.err.println("❌ LỖI VĂN BẢN: Đập File không thủng, Chặn lối: " + e.getMessage());
        }
    }

    /**
     * HÀM ĐỌC FILE (Tải ổ đĩa cứng bay vào Bộ RAM mềm chạy nhanh).
     */
    private void loadAlertsFromFile() {
        File file = new File(ALERT_FILE);
        // Tránh bị Crash nếu chạy lần đầu, Folder alert đó làm vái đã có File? -> Ráng
        // rào lại đỡ chết sập!
        if (!file.exists()) {
            return;
        }

        alerts.clear(); // Xả đi.

        // FileReader (Kính lúp bé chọc từng kí tự) -> Đưa qua BufferReader (Cái xẻng
        // xúc khổng lồ gom theo từng dòng)
        try (BufferedReader reader = new BufferedReader(new FileReader(ALERT_FILE))) {
            String line;
            // .readLine() sẽ ăn mòn từng Dòng trong file. Đến khi ăn thấy chữ "Rác rỗng
            // (null)" thì nhả miệng ra.
            while ((line = reader.readLine()) != null) {
                alerts.add(line);
            }
        } catch (IOException e) {
            System.err.println("❌ LỖI ĐỌC FILE TẠI LOAD: " + e.getMessage());
        }
    }
}