/**
 * monitor.js — Hiển thị log mạng theo thời gian thực cho blue team.
 *
 * Mục tiêu:
 * - Gọi /api/logs để lấy dữ liệu log mới nhất
 * - Phân loại mức độ nguy hiểm theo score
 * - Cập nhật trạng thái hệ thống và hiển thị lên bảng
 */

let monitorIntervalId = null;

/**
 * refreshMonitorLogs()
 * Lấy các log gần nhất từ backend và render lại bảng giám sát.
 * Hàm này còn cập nhật trạng thái "Đang kết nối..." theo thời gian thực.
 */
async function refreshMonitorLogs() {
    const logs = await fetchData('/logs');
    const tbody = document.getElementById('monitor-table-body');

    if (!tbody) return;
    if (!Array.isArray(logs)) return;

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
        const status = log.status || 'PASS';

        // Ngưỡng nguy hiểm được căn theo SecurityBot.
        let severity = 'severity-low';
        if (risk >= 45) severity = 'severity-critical';
        else if (risk >= 30) severity = 'severity-high';
        else if (risk >= 15) severity = 'severity-medium';

        const row = document.createElement('tr');

        if (severity === 'severity-critical') {
            row.classList.add('row-critical');
        }
        if (severity === 'severity-medium') {
            row.classList.add('row-warning');
        }

        let attackBadgeClass = 'status-badge';
        if (log.attack === 'BRUTE_FORCE') attackBadgeClass += ' severity-critical';
        else if (log.attack === 'REQUEST_FLOOD') attackBadgeClass += ' severity-high';
        else if (log.attack === 'UNKNOWN_ATTACK') attackBadgeClass += ' severity-medium';

        row.innerHTML = `
            <td>${log.time || '-'}</td>
            <td><strong>${log.ip || 'N/A'}</strong></td>
            <td>${log.action || '-'}</td>
            <td><span class="${attackBadgeClass}">${log.attack || 'NORMAL'}</span></td>
            <td class="${severity}">${risk}</td>
            <td>
                <span class="status-badge">${status}</span>
            </td>
        `;

        tbody.appendChild(row);
    });

    // Cập nhật trạng thái ở góc trên header của trang monitor.
    const indicator = document.getElementById('update-indicator');
    if (indicator) {
        const now = new Date().toLocaleTimeString('vi-VN');
        indicator.innerHTML = `● Hệ thống đang giám sát lưu lượng mạng theo thời gian thực: [${now}]`;
    }
}

// Khởi chạy khi DOM đã sẵn sàng.
document.addEventListener('DOMContentLoaded', () => {
    refreshMonitorLogs();

    if (monitorIntervalId) clearInterval(monitorIntervalId);
    monitorIntervalId = setInterval(refreshMonitorLogs, 1000);
});

window.addEventListener('beforeunload', () => {
    if (monitorIntervalId) clearInterval(monitorIntervalId);
});