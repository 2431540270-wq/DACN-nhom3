package service;

import java.time.LocalDateTime;
import java.util.Random;
import model.LogEntry;
import database.LogDAO;

/**
 * LogGenerator — Tạo log giả ngẫu nhiên và lưu vào database.
 *
 * Chạy vòng lặp vô hạn, mỗi 1 giây tạo 1 log gồm:
 * - IP ngẫu nhiên (IPv4 dải 192.168.1.x)
 * - Action ngẫu nhiên: LOGIN_FAIL, LOGIN_SUCCESS, REQUEST
 * - Status: SUSPICIOUS (nếu LOGIN_FAIL), PASS (còn lại)
 * - AttackType: luôn là NORMAL
 *
 * Sau khi tạo, gọi LogDAO.insertLog() để lưu vào MySQL.
 */
public class LogGenerator {

    // Danh sách các action có thể sinh ngẫu nhiên
    private static final String[] ACTIONS = {
            "LOGIN_FAIL",
            "LOGIN_SUCCESS",
            "REQUEST"
    };

    // DAO để ghi log vào database
    private LogDAO logDAO = new LogDAO();

    // Random dùng chung để sinh số ngẫu nhiên
    private Random random = new Random();

    /**
     * Vòng lặp chính: tạo log → lưu DB → in console → sleep 2 giây.
     * Chạy mãi mãi cho đến khi chương trình bị dừng.
     */
    public void startGenerating() {
        System.out.println("[LogGenerator] Bắt đầu sinh log...");

        while (true) {
            try {
                // === Bước 1: Sinh dữ liệu ngẫu nhiên ===
                String ip = randomIP(); // VD: 192.168.1.42
                String action = randomAction(); // VD: LOGIN_FAIL
                String time = LocalDateTime.now().toString().replace("T", " ");
                String status = mapStatus(action); // VD: SUSPICIOUS
                String attackType = "NORMAL"; // Luôn là NORMAL

                // === Bước 2: Tạo LogEntry với constructor (time, ip, action) ===
                LogEntry log = new LogEntry(time, ip, action);

                // === Bước 3: Gán thêm status và attackType ===
                log.setStatus(status);
                log.setAttackType(attackType);

                // === Bước 4: Lưu vào database thông qua LogDAO ===
                logDAO.insertLog(log);

                // === Bước 5: In ra console để theo dõi ===
                System.out.println("[LOG] " + ip + " - " + action + " - " + status);

                // === Nghỉ 1 giây trước khi tạo log tiếp ===
                Thread.sleep(1000);

            } catch (InterruptedException e) {
                // Xử lý khi thread bị interrupt (dừng chương trình)
                System.err.println("[LogGenerator] Đã dừng sinh log.");
                break;
            }
        }
    }

    /**
     * Sinh địa chỉ IP ngẫu nhiên dạng 192.168.1.x (x từ 1 đến 254).
     *
     * @return Địa chỉ IPv4 ngẫu nhiên
     */
    private String randomIP() {
        // Tạo 4 octet ngẫu nhiên cho địa chỉ IP
        int a = random.nextInt(256); // 0-255
        int b = random.nextInt(256); // 0-255
        int c = random.nextInt(256); // 0-255
        int d = random.nextInt(256); // 0-255
        return a + "." + b + "." + c + "." + d;
    }

    /**
     * Chọn ngẫu nhiên 1 action từ danh sách ACTIONS.
     *
     * @return LOGIN_FAIL, LOGIN_SUCCESS hoặc REQUEST
     */
    private String randomAction() {
        return ACTIONS[random.nextInt(ACTIONS.length)];
    }

    /**
     * Mapping action → status theo quy tắc:
     * LOGIN_FAIL → SUSPICIOUS (đáng ngờ)
     * LOGIN_SUCCESS → PASS (bình thường)
     * REQUEST → PASS (bình thường)
     *
     * @param action Loại action
     * @return Status tương ứng
     */
    private String mapStatus(String action) {
        if ("LOGIN_FAIL".equals(action)) {
            return "SUSPICIOUS";
        }
        return "PASS";
    }
}
