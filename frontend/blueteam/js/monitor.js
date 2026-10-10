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

    const logs = await fetchData('/logs');

    const tbody = document.getElementById('monitor-table-body');

    if (!tbody) return;
    if (!logs || !Array.isArray(logs)) return;

    tbody.innerHTML = '';

    if (logs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">
                Đang chờ nhận dữ liệu
                </td>
            </tr>
        `;
        return;
    }

    logs.forEach(log => {

        const risk = log.score || 0;
        const status = log.status || "PASS";

        let severity = "severity-low";

        // Ngưỡng khớp với SecurityBot: 15=SUSPICIOUS, 30=MONITORING, 45=BLOCKED
        if (risk >= 45) severity = "severity-critical";
        else if (risk >= 30) severity = "severity-high";
        else if (risk >= 15) severity = "severity-medium";

        const row = document.createElement('tr');

        if (severity === "severity-critical") {
            row.classList.add("row-critical");
        }
        if (severity === "severity-medium") {
            row.classList.add("row-warning");
        }

        let attackBadgeClass = "status-badge";
        if (log.attack === "BRUTE_FORCE") attackBadgeClass += " severity-critical";
        else if (log.attack === "REQUEST_FLOOD") attackBadgeClass += " severity-high";
        else if (log.attack === "UNKNOWN_ATTACK") attackBadgeClass += " severity-medium";

        row.innerHTML = `
        <td>${log.time || '-'}</td>
        <td><strong>${log.ip || 'N/A'}</strong></td>
        <td>${log.action || '-'}</td>
        <td><span class="${attackBadgeClass}">${log.attack || 'NORMAL'}</span></td>
        <td class="${severity}">${risk}</td>
        <td>
            <span class="status-badge">
                ${status}
            </span>
        </td>
        `;

        tbody.appendChild(row);
    });

    const indicator = document.getElementById('update-indicator');
    if (indicator) {
        const now = new Date().toLocaleTimeString('vi-VN');
        indicator.innerHTML = `● Hệ thống đang giám sát lưu lượng mạng theo thời gian thực: [${now}]`;
    }
}

// Trang sẽ reload mỗi 1s để phù hợp với logic
const monitorInterval = setInterval(refreshMonitorLogs, 1000);

// Nạp dữ liệu khi DOM sẵn sàng
document.addEventListener('DOMContentLoaded', refreshMonitorLogs);

// Dọn interval khi rời tab
window.addEventListener('beforeunload', () => clearInterval(monitorInterval));