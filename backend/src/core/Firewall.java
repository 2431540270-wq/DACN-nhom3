package core;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Firewall — Quản lý danh sách IP bị chặn (blocklist).
 * 
 * Chức năng:
 * - Thêm IP vào blocklist (blockIP)
 * - Kiểm tra IP có bị chặn không (isBlocked)
 * - Lấy toàn bộ danh sách IP bị chặn (getBlockedIPs)
 * 
 * Thread-safety: Sử dụng Collections.synchronizedSet()
 * để an toàn khi truy xuất từ nhiều thread (API + Monitor).
 */
public class Firewall {

    /** Tập hợp IP bị chặn — thread-safe */
    private final Set<String> blockedIPs = Collections.synchronizedSet(new HashSet<>());

    /**
     * Thêm một IP vào danh sách chặn.
     * Nếu IP đã tồn tại trong danh sách, không có thay đổi (Set đảm bảo unique).
     *
     * @param ip Địa chỉ IP cần chặn (VD: "192.168.1.15")
     */
    public void blockIP(String ip) {
        blockedIPs.add(ip);
        System.out.println("[Firewall] Đã BLOCK IP: " + ip);
    }

    /**
     * Gỡ một IP khỏi danh sách chặn.
     * Nếu IP không tồn tại trong danh sách, không có thay đổi.
     *
     * @param ip Địa chỉ IP cần gỡ chặn (VD: "192.168.1.15")
     */
    public void unblockIP(String ip) {
        blockedIPs.remove(ip);
        System.out.println("[Firewall] Đã GỠ CHẶN IP: " + ip);
    }

    /**
     * Kiểm tra xem một IP có đang bị chặn hay không.
     *
     * @param ip Địa chỉ IP cần kiểm tra
     * @return true nếu IP đang bị chặn, false nếu không
     */
    public boolean isBlocked(String ip) {
        return blockedIPs.contains(ip);
    }

    /**
     * Lấy toàn bộ danh sách IP đang bị chặn.
     * 
     * [FIX LỖI 13] Trả về SNAPSHOT (đản tránh concurrent access)
     * thay vì reference trực tiếp — an toàn khi ApiServer duyệt từ thread khác.
     *
     * @return Set<String> bản sao của danh sách IP bị chặn
     */
    public Set<String> getBlockedIPs() {
        return new HashSet<>(blockedIPs);
    }
}