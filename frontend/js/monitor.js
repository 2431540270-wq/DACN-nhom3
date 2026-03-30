/**
 * monitor.js — KỊCH BẢN VẼ LÊN SỰ TRỰC QUAN SINH ĐỘNG NHẤT CỦA BẢN ĐỒ LOG GIÁO ÁN.
 * 
 * Mục đích file này:
 *   - Nó như Cứ Tượng Camera! Đảo Mắt Xin '/logs' Dữ liệu mỗi 3s 1 Lần liên tụ tì (Bằng Gọi Loop setInterval).
 *   - Lấy Mớ Gốc Củ Rụng Ở API (Array Mảng Log [ A, B, C ])
 *   - Trộn Xào Biến Gắn Thẻ `<tr class="...">`, Ráp Cho Trình Duyệt Bày Mâm Cỗ Bàn Lên HTML Màn Lọc.
 *   - Rất Đỉnh Ở Điểm: Nạp CLASS CSS SÁNG CHÓI CHO NHỮNG LOG MANG ĐIỂM RISK ĐẦY UY LỰC (Nhấp Chớp Đỏ Cảnh Báo Ngon Lành Tích Nhất Dashboard).
 */

async function refreshMonitorLogs() {

    // Thằng Grab Nhận Hàng Đi Gọi Đồ Ăn Cho Admin Về (Dữ liệu Raw Java Text 100 Cuốn).
    const logs = await fetchData('/logs');

    const tbody = document.getElementById('monitor-table-body');

    // Mất Cửa Sổ Table Để Gói Xôi Lá Chuối Ở Đâu Hả Browser? (Về Cốt Khỏi Chạy Lỗi Chết Mã Bị Phốt Null Trên Đóm Chrome Error) 
    if (!tbody) return;
    if (!logs || !Array.isArray(logs)) return;

    // Xé Toạc Lớp Vỏ Dối Trá Table Cũ Kĩ Rác Trước. Vẽ Màn Hình Phẳng Vị! Trắng Sáng Nhất !
    tbody.innerHTML = '';

    // Guard (Rào Trắng Khác Bọt): Tránh Cảnh Web Trống Huơ Trống Hoác Khi Không Có Data.
    if (logs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">
                    Biển Log Đang Êm Đềm Chua Lên Khúc Giao Mùa Đâu Bạn MÌNH! Gõ Lệnh Chơi Bời Gì Vô Chưa...
                </td>
            </tr>
        `;
        return;
    }

    // Cò Lết Bới Đống Rác Thơm Thơm Lộn Nồi
    logs.forEach(log => {

        // Phòng Hỡ Củi Trống Thiếu Cửa Tắt Máy! Dốt Toán Học Trả 0. Trống Nhãn Gài "PASS" (Đỗ Pass An Toàn Sinh Viên Khách Bến Vắng)
        const risk = log.score || 0;
        const status = log.status || "PASS";

        // Logic CSS TO THE TOP: KỸ THUẬT RẼ NHÁNH IF-ELSE Chuyển Số Nguyên Toán Học -> Trạng Thái Chữ Giao Diện Web CSS Rẽ Quạt!
        // Nếu risk Của Mày Lên > 80 (Bị Khóa Đít Rồi)? Ồ Tốt. Ta gắn Áo Số "Critical Đỏ Hoành Tráng Nhấp Nháy Hú CÒI" CSS Mặc Cho Mày Khoác Gánh!
        let severity = "severity-low"; // Giả Ngoan Bọc áo Xanh Chanh Dân Nghèo Mặc Định Lúc Đầu Cút

        if (risk >= 80) severity = "severity-critical";
        else if (risk >= 50) severity = "severity-high";
        else if (risk >= 20) severity = "severity-medium";

        // JS Gõ Vào Não Browser: "Nhớ Đẻ Cho Em Thẻ <tr> Cha Nha A Trình Duyệt"
        const row = document.createElement('tr');

        // Animation Đỉnh Khao CSS Nhấp Chớp Ở Dây Là Khúc Này!!! (Đẩy Cho Table Đẹp Mê Man Điểm Số Tốt Web)
        if (severity === "severity-critical") {
            // CSS `.row-critical` Sẽ CÓ TÍNH CHẤT Làm Màn Nền Dòng Rực ĐỎ Mờ - Lóa Nhấp Nháy! Xéo Chữ!
            row.classList.add("row-critical");
        }
        if (severity === "severity-medium") {
            row.classList.add("row-warning"); // Warning Thì Vàng Óng Chói Khựa Bền Viền!
        }

        row.innerHTML = `
        <td>${log.time || '-'}</td>
        <td><strong>${log.ip || 'N/A'}</strong></td>
        <td>${log.action || '-'}</td>
        <td class="${severity}">${risk}</td>
        <td>
            <span class="status-badge">
                ${status}
            </span>
        </td>
        `;

        tbody.appendChild(row); // Append là Nhét Thêm Cục Lego <tr> Giữa Cái Lõng Thùng Cái Bàn Lớn Tbody
    });

    // Cuối Cùng Dành Tặng Điễm Tín Nghĩa Lịch Sự - Vẽ Con Số Cái Tích Tắc Đồng Hồ Vào DIV Phía Đáy Gốc Khung Rạch
    const indicator = document.getElementById('update-indicator');
    if (indicator) {
        // Gắn Bộ Số Địa Phương Cấp Phá Vòng Clock Cho Máy Này Lại (21:30:11)
        const now = new Date().toLocaleTimeString('vi-VN');
        indicator.innerHTML = `● Hệ thống đang giám sát lưu lượng mạng theo thời gian thực: [${now}]`;
    }
}

// [FIX LỖI 10] Tăng từ 1000ms lên 2000ms để giảm tải backend
// Monitor page là real-time display chính nên giữ 2s, đủ responsive
const monitorInterval = setInterval(refreshMonitorLogs, 2000);

// Nạp dữ liệu khi DOM sẵn sàng
document.addEventListener('DOMContentLoaded', refreshMonitorLogs);

// Dọn interval khi rời tab
window.addEventListener('beforeunload', () => clearInterval(monitorInterval));