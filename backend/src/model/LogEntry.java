package model;

/**
 * LogEntry — Model đại diện cho một dòng log mạng.
 * 
 * Chứa thông tin:
 * - time: Timestamp khi đọc log
 * - ip: Địa chỉ IP nguồn
 * - action: Hành động (LOGIN_FAIL, LOGIN_SUCCESS, REQUEST)
 * - score: Điểm rủi ro do SecurityBot tính (0-100, default: 0)
 * - status: Trạng thái (PASS, SUSPICIOUS, MONITORING, BLOCKED)
 * - attackType: Loại tấn công (NORMAL, BRUTE_FORCE, REQUEST_FLOOD)
 * 
 * score, status, attackType được SecurityBot gán SAU KHI phân tích.
 */
public class LogEntry {

    /** ID trong database (0 nếu chưa lưu vào DB) */
    private int id;

    /** Timestamp khi đọc log */
    private String time;

    /** Địa chỉ IP nguồn */
    private String ip;

    /** Hành động ghi nhận (LOGIN_FAIL, LOGIN_SUCCESS, REQUEST) */
    private String action;

    /** Điểm rủi ro (0-100), do SecurityBot tính — default: 0 */
    private int score;

    /** Trạng thái sau phân tích — default: "PASS" */
    private String status;

    /** Loại tấn công được phát hiện — default: "NORMAL" */
    private String attackType;

    /** Mô tả chi tiết (từ database, có thể null) */
    private String description;

    /**
     * Khởi tạo LogEntry với dữ liệu cơ bản từ file log.
     * Các trường score/status/attackType sẽ được SecurityBot cập nhật sau.
     *
     * @param time   Timestamp (ISO format)
     * @param ip     Địa chỉ IP nguồn (VD: "192.168.1.15")
     * @param action Hành động (VD: "LOGIN_FAIL")
     */
    public LogEntry(String time, String ip, String action) {
        this.time = time;
        this.ip = ip;
        this.action = action;
        this.score = 0;
        this.status = "PASS";
        this.attackType = "NORMAL";
    }

    // ===================== GETTERS =====================

    /** @return ID trong database */
    public int getId() {
        return id;
    }

    /**
     * @return Timestamp của log entry
     */
    public String getTime() {
        return time;
    }

    /**
     * @return Địa chỉ IP nguồn
     */
    public String getIp() {
        return ip;
    }

    /**
     * @return Hành động ghi nhận (LOGIN_FAIL, LOGIN_SUCCESS, REQUEST)
     */
    public String getAction() {
        return action;
    }

    /**
     * @return Điểm rủi ro (0-100)
     */
    public int getScore() {
        return score;
    }

    /**
     * @return Trạng thái hiện tại (PASS, SUSPICIOUS, MONITORING, BLOCKED)
     */
    public String getStatus() {
        return status;
    }

    /**
     * @return Loại tấn công (NORMAL, BRUTE_FORCE, REQUEST_FLOOD)
     */
    public String getAttackType() {
        return attackType;
    }

    /** @return Mô tả chi tiết */
    public String getDescription() {
        return description;
    }

    // ===================== SETTERS =====================

    /**
     * Cập nhật điểm rủi ro (được gọi bởi SecurityBot).
     *
     * @param score Điểm rủi ro mới (0-100)
     */
    public void setScore(int score) {
        this.score = score;
    }

    /**
     * Cập nhật trạng thái (được gọi bởi SecurityBot).
     *
     * @param status Trạng thái mới (PASS/SUSPICIOUS/MONITORING/BLOCKED)
     */
    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * Cập nhật loại tấn công (được gọi bởi SecurityBot).
     *
     * @param attackType Loại tấn công (NORMAL/BRUTE_FORCE/REQUEST_FLOOD)
     */
    public void setAttackType(String attackType) {
        this.attackType = attackType;
    }

    /** Gán ID database */
    public void setId(int id) {
        this.id = id;
    }

    /** Gán mô tả chi tiết */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Biểu diễn dạng chuỗi để debug.
     *
     * @return Chuỗi mô tả LogEntry
     */
    @Override
    public String toString() {
        return "[" + time + "] " + ip + " " + action
                + " | score=" + score
                + " | status=" + status
                + " | attack=" + attackType;
    }
}