package service;

import alert.AlertSystem;
import java.util.*;

/**
 * AttackDetector — Phát hiện tấn công mạng dựa trên ngưỡng.
 * 
 * Phát hiện 2 loại tấn công:
 *   - BRUTE_FORCE: IP có >= 5 lần LOGIN_FAIL
 *   - REQUEST_FLOOD: IP có >= 10 lần REQUEST
 * 
 * Lưu ý: Class này hiện CHƯA ĐƯỢC SỬ DỤNG trong luồng chính.
 * Logic detect đã được tích hợp trực tiếp trong SecurityBot
 * với ngưỡng khác (BRUTE_FORCE >= 5, REQUEST_FLOOD >= 20).
 * Giữ lại để có thể sử dụng khi cần tách logic.
 */
public class AttackDetector {

    /** Ngưỡng LOGIN_FAIL để coi là brute force */
    private static final int LOGIN_FAIL_THRESHOLD = 5;

    /** Ngưỡng REQUEST để coi là request flood */
    private static final int REQUEST_THRESHOLD = 10;

    /**
     * Phát hiện tấn công dựa trên bản đồ LOGIN_FAIL và REQUEST theo IP.
     * 
     * Quy trình:
     *   1. Duyệt loginFailMap — nếu count >= 5 → đánh dấu BRUTE_FORCE
     *   2. Duyệt requestMap — nếu count >= 10 → đánh dấu REQUEST_FLOOD
     *   3. Gửi cảnh báo qua AlertSystem cho mỗi IP bị phát hiện
     *
     * @param loginFailMap Map<IP, SốLầnFail> từ LogAnalyzer
     * @param requestMap   Map<IP, SốLầnRequest> từ LogAnalyzer
     * @param alert        AlertSystem để ghi cảnh báo
     * @return Map<IP, LoạiTấnCông> danh sách IP bị phát hiện tấn công
     */
    public Map<String, String> detect(
            Map<String, Integer> loginFailMap,
            Map<String, Integer> requestMap,
            AlertSystem alert) {

        Map<String, String> detected = new HashMap<>();

        // Phát hiện Brute Force — >= 5 lần LOGIN_FAIL từ cùng IP
        for (String ip : loginFailMap.keySet()) {

            int count = loginFailMap.get(ip);

            if (count >= LOGIN_FAIL_THRESHOLD) {

                String attackType = "BRUTE_FORCE";
                detected.put(ip, attackType);

                String msg = "🚨 IP " + ip
                        + " nghi ngờ BRUTE FORCE (" + count + " LOGIN_FAIL)";
                alert.addAlert(msg);
            }
        }

        // Phát hiện Request Flood — >= 10 lần REQUEST từ cùng IP
        for (String ip : requestMap.keySet()) {

            int count = requestMap.get(ip);

            if (count >= REQUEST_THRESHOLD) {

                String attackType = "REQUEST_FLOOD";
                detected.put(ip, attackType);

                String msg = "⚠ IP " + ip
                        + " gửi REQUEST bất thường (" + count + " lần)";
                alert.addAlert(msg);
            }
        }

        return detected;
    }
}