package service;

import java.util.*;
import model.LogEntry;

/**
 * LogAnalyzer — Phân tích và thống kê log mạng theo action và IP.
 * 
 * Cung cấp 2 chức năng:
 *   - countAction(): Đếm số lần xuất hiện của một action cụ thể theo IP
 *   - sortByIp(): Sắp xếp danh sách log theo địa chỉ IP
 * 
 * Được sử dụng chính bởi SecurityBot để tính Risk Score.
 */
public class LogAnalyzer {

    /**
     * Đếm số lần xuất hiện của một action cụ thể, nhóm theo IP.
     * 
     * Ví dụ: countAction(logs, "LOGIN_FAIL") với dữ liệu:
     *   192.168.1.15 LOGIN_FAIL (x5)
     *   192.168.1.20 LOGIN_FAIL (x2)
     * → Kết quả: {"192.168.1.15": 5, "192.168.1.20": 2}
     *
     * @param logs   Danh sách LogEntry cần phân tích
     * @param action Tên action cần đếm (VD: "LOGIN_FAIL", "REQUEST", "LOGIN_SUCCESS")
     * @return Map<IP, SốLần> — số lần action xuất hiện cho mỗi IP
     */
    public Map<String, Integer> countAction(List<LogEntry> logs, String action) {

        Map<String, Integer> map = new HashMap<>();

        for (LogEntry log : logs) {
            // So sánh action — dùng equals() an toàn (tránh NullPointerException)
            if (action.equals(log.getAction())) {
                String ip = log.getIp();
                map.put(ip, map.getOrDefault(ip, 0) + 1);
            }
        }

        return map;
    }

    /**
     * Sắp xếp danh sách log theo địa chỉ IP (alphabetical).
     * 
     * Lưu ý: Method này SẼ THAY ĐỔI list gốc (in-place sort).
     * Nếu cần giữ list gốc, hãy truyền bản sao.
     *
     * @param logs Danh sách LogEntry cần sắp xếp
     * @return Danh sách đã sắp xếp (cùng reference với input)
     */
    public List<LogEntry> sortByIp(List<LogEntry> logs) {
        logs.sort(Comparator.comparing(LogEntry::getIp));
        return logs;
    }
}
