package core;

/**
 * IPProfile — Model lưu trữ hồ sơ hành vi của một địa chỉ IP.
 * 
 * Theo dõi: số lần LOGIN_FAIL, LOGIN_SUCCESS, REQUEST
 * và tính Risk Score dựa trên công thức trọng số.
 * 
 * Lưu ý: Class này hiện CHƯA ĐƯỢC SỬ DỤNG trong luồng chính.
 * Logic tương tự đã được tích hợp trực tiếp trong SecurityBot.
 * Giữ lại để có thể refactor sau (tách logic ra khỏi SecurityBot).
 * 
 * Công thức Risk Score:
 * riskScore = (loginFail * 3) + (request * 1) - (loginSuccess * 2)
 * Clamp tối thiểu: 0
 */
public class IPProfile {

    /** Địa chỉ IP */
    private String ip;

    /** Số lần đăng nhập thất bại */
    private int loginFail;

    /** Số lần đăng nhập thành công */
    private int loginSuccess;

    /** Số lần gửi request */
    private int request;

    /** Điểm rủi ro tính được */
    private int riskScore;

    /**
     * Khởi tạo IPProfile cho một địa chỉ IP.
     * Tất cả counter bắt đầu từ 0.
     *
     * @param ip Địa chỉ IP (VD: "192.168.1.15")
     */
    public IPProfile(String ip) {
        this.ip = ip;
    }

    /**
     * Tăng bộ đếm LOGIN_FAIL lên 1.
     */
    public void increaseFail() {
        loginFail++;
    }

    /**
     * Tăng bộ đếm LOGIN_SUCCESS lên 1.
     */
    public void increaseSuccess() {
        loginSuccess++;
    }

    /**
     * Tăng bộ đếm REQUEST lên 1.
     */
    public void increaseRequest() {
        request++;
    }

    /**
     * Tính Risk Score dựa trên công thức trọng số.
     * 
     * Công thức: (loginFail * 3) + (request * 1) - (loginSuccess * 2)
     * 
     * - LOGIN_FAIL có trọng số cao nhất (x3) vì là dấu hiệu tấn công rõ ràng
     * - REQUEST có trọng số thấp (x1) vì có thể là traffic bình thường
     * - LOGIN_SUCCESS giảm bớt nghi ngờ (x2) vì chứng tỏ người dùng hợp lệ
     * 
     * Kết quả được clamp tối thiểu 0 (không cho phép score âm).
     */
    public void calculateRiskScore() {
        riskScore = (loginFail * 3) + (request * 1) - (loginSuccess * 2);

        if (riskScore < 0) {
            riskScore = 0;
        }
    }

    // ===================== GETTERS =====================

    /**
     * @return Điểm rủi ro đã tính (gọi calculateRiskScore() trước)
     */
    public int getRiskScore() {
        return riskScore;
    }

    /**
     * @return Địa chỉ IP
     */
    public String getIp() {
        return ip;
    }

    /**
     * @return Số lần LOGIN_FAIL
     */
    public int getLoginFail() {
        return loginFail;
    }

    /**
     * @return Số lần LOGIN_SUCCESS
     */
    public int getLoginSuccess() {
        return loginSuccess;
    }

    /**
     * @return Số lần REQUEST
     */
    public int getRequest() {
        return request;
    }
    // [FIX LỖI 8] ĐÃ XÓA: setLastAccess(long) và increaseRequestCount() — 2 method stub rỗng
    // không thực hiện bất kỳ logic gì, gây hiểu nhầm về chức năng của class.
}