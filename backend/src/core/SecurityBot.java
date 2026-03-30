package core;

import java.util.*;
import model.LogEntry;
import alert.AlertSystem;
import service.LogAnalyzer;

public class SecurityBot {

    private Map<String, Integer> dangerHistory = new HashMap<>();

    /**
     * Firewall (Bức tường lửa). Nếu Bot thấy ác quá, lệnh Firewall chặn nó ngay.
     */
    private Firewall firewall = new Firewall();

    /**
     * HÀM LÕI: Phân Tích Sự Độc Hại của Danh Sách Log
     * 
     * @param logs        Danh sách khổng lồ các sự kiện mạng (LogEntry).
     * @param alertSystem Hệ thống Chuông thông báo (để hò hét lên cái Alert Table
     *                    HTML).
     */
    public void analyze(List<LogEntry> logs, AlertSystem alertSystem) {

        LogAnalyzer analyzer = new LogAnalyzer();

        // Bước 1: Bảo thằng đệ đếm xem với từng IP thì nó có bao nhiêu lần gõ sai Pass,
        // gọi lệnh, và thành công
        // vd: failMap -> {"192.168.1.15" : 5 lần fail, "8.8.8.8" : 0 lần fail }
        Map<String, Integer> failMap = analyzer.countAction(logs, "LOGIN_FAIL");

        Map<String, Integer> requestMap = analyzer.countAction(logs, "REQUEST");

        Map<String, Integer> successMap = analyzer.countAction(logs, "LOGIN_SUCCESS");

        // Bước 2: Gom chung toàn bộ các IP mà 3 thằng kia tìm thấy vào 1 rổ Set duy
        // nhất.
        // Set ưu điểm là nếu trùng IP thì nó tự vứt thằng trùng, nên danh sách lúc nào
        // cũng Unique (duy nhất).
        Set<String> allIPs = new HashSet<>();
        allIPs.addAll(failMap.keySet());
        allIPs.addAll(requestMap.keySet());
        allIPs.addAll(successMap.keySet());

        // Bước 3: Duyệt lần lượt, thăm khám sức khỏe cho từng IP trong rổ.
        for (String ip : allIPs) {

            if (firewall.isBlocked(ip)) {
                updateLogsForIP(logs, ip, 100, "BLOCKED", "BLOCKED");
                continue;
            }

            int fail = failMap.getOrDefault(ip, 0);
            int request = requestMap.getOrDefault(ip, 0);
            int success = successMap.getOrDefault(ip, 0);
            int history = dangerHistory.getOrDefault(ip, 0);

            // BƯỚC QUAN TRỌNG: CÔNG THỨC CHẤM ĐIỂM (RISK SCORE)
            // Lỗi càng nặng điểm càng cao. Thành công nhiều thì được giảm nhẹ hình phạt.
            int riskScore = (fail * 3) // Sai Pass -> Trọng số rất gắt (x3). Nhập sai là cực kì nguy hại (BRUTE FORCE)
                    + (request * 1) // Request -> Gửi Ping thử (x1). Bình thường.
                    - (success * 2) // Login thành công (Trừ 2 số).
                    + (history * 5); // Tiền án (x5). Trước mày cớ dã tâm rồi thì nay tao phạt x5.

            // Lỡ có thằng đăng nhập đúng nhiều quá khiến biến Risk bị âm (lỗ) -> Trả về nhỏ
            // nhất là 0 thôi
            riskScore = Math.max(riskScore, 0);

            // Bước 4: Chẩn Đoán Loại Bệnh (Tấn Công)
            String attackType = "NORMAL"; // Mặc định là Thường Dân.
            if (fail >= 5) {
                attackType = "BRUTE_FORCE"; // Dò mật khẩu liên tục (Brute Force).
            } else if (request >= 20) {
                attackType = "REQUEST_FLOOD"; // Cố tình ấn DDoS cái máy chủ bằng cả chục nốt ấn 1 giây (Request Flood)
            }

            // Bước 5: Ra Lệnh Thực Thi Hình Phạt (Block hoặc Cảnh Báo)
            String status = "PASS"; // Trạng thái vượt qua cửa ải bình thường.

            if (riskScore >= 15) { // Nếu lớn hơn 15đ, bắt đầu có biến...

                // Đánh dấu lại tiền sự của thằng này vào tủ hồ sơ.
                int level = history + 1;
                dangerHistory.put(ip, level);

                String message; // Cầm sẵn phong bì viết thư nôn báo động cáo cấp

                if (riskScore >= 30) {
                    // Cấp Rất Nguy Kịch (Khóa luôn Mõm của IP này)!
                    firewall.blockIP(ip); // Gọi Tường Lửa nhốt nó
                    status = "BLOCKED"; // Đổi trạng thái

                    // Dòng báo cáo đỏ tươi cho HTML vẽ lên.
                    message = "🚨 CRITICAL " + attackType + " IP " + ip +
                            " | Risk Score: " + riskScore +
                            " | IP đã bị BLOCK";

                } else if (riskScore >= 20) {
                    // Cấp Cao (Nhưng chưa giam, cho người ta chú ý trên bảng)
                    status = "MONITORING";

                    message = "🔴 HIGH RISK " + attackType + " IP " + ip +
                            " | Risk Score: " + riskScore;

                } else {
                    // Cấp Nghi vờ bấu.
                    status = "SUSPICIOUS";

                    message = "⚠ Suspicious " + attackType + " IP " + ip +
                            " | Risk Score: " + riskScore;
                }

                alertSystem.addAlert(message); // Nhét lá thư vừa viết vào phong bì gửi lên loa phóng thanh.
            }

            // Cuối cùng: Nhờ hàm đệ lấy cây cọ Quét lại toàn bộ Danh sách log (Cho điểm của
            // từng log entry đúng bằng RiskScore của chính cái IP Sinh nó ra)
            updateLogsForIP(logs, ip, riskScore, status, attackType);
        }
    }

    /**
     * HÀM PHỤ: CẬP NHẬT TRẠNG THÁI CHO TẤT CẢ FILE LOGS
     * Vì ban đầu lúc load ở Text file, log chỉ cầm mỗi IP Action (vd 1.1.1.1 -
     * LOGIN), nó chưa hề
     * biết điểm Rủi ro là ai và bị Chặn (status) ra sao. Do đó khi duyệt xong thuật
     * toán, ta quay lại áp đặt các thẻ này.
     *
     * @param logs      Danh sách log cần cập nhật
     * @param ip        Địa chỉ IP cần tìm trong list để Modify
     * @param riskScore Điểm đã được toán học hóa -> đem Apply.
     * @param status    Trạng thái gán nhãn
     */
    private void updateLogsForIP(List<LogEntry> logs, String ip,
            int riskScore, String status, String attackType) {
        // Vòng lặp For qua từng hạt đậu đen (Logs)
        for (LogEntry log : logs) {
            // Nếu hạt đậu thuộc quyền sở hữu của nông dân tên là ip...
            if (log.getIp().equals(ip)) {
                // Áp đặt sự chê bai / khen ngợi
                log.setScore(riskScore);
                log.setStatus(status);
                log.setAttackType(attackType);
            }
        }
    }

    /**
     * @return Bứng class Firewall gửi ra chỗ khác nếu bên ngoài cần (Ví dụ file
     *         ApiServer.java cần).
     */
    public Firewall getFirewall() {
        return firewall;
    }
}