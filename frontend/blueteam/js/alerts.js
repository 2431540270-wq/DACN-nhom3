/**
 * alerts.js — Hiển thị danh sách cảnh báo bảo mật.
 *
 * Mục tiêu:
 * - Gọi /api/alerts để lấy danh sách cảnh báo từ backend
 * - Đếm số lượng theo mức độ: Critical, High, Medium, Low
 * - Cho phép admin block IP ngay từ danh sách cảnh báo
 */

let alertsIntervalId = null;

/**
 * loadAlerts()
 * Lấy dữ liệu cảnh báo từ backend và render lên bảng.
 * Đồng thời tính số lượng cảnh báo theo mức độ để hiển thị trên các card thống kê.
 */
async function loadAlerts() {
    const alerts = await fetchData('/alerts');
    const tbody = document.getElementById('alerts-list-body');

    if (!tbody) return;
    if (!Array.isArray(alerts)) return;

    tbody.innerHTML = '';

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    if (alerts.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">
                    Không có cảnh báo nào
                </td>
            </tr>
        `;
    } else {
        alerts.forEach(alert => {
            const level = alert.level || 'LOW';
            const score = alert.score || 0;
            const time = alert.time || '-';
            const attack = alert.attack || 'UNKNOWN';
            const ip = alert.ip || 'N/A';

            if (level === 'CRITICAL') critical++;
            else if (level === 'HIGH') high++;
            else if (level === 'MEDIUM') medium++;
            else low++;

            const severityClass = `severity-${level.toLowerCase()}`;
            const row = document.createElement('tr');

            row.innerHTML = `
                <td>${time}</td>
                <td class="${severityClass}">${level}</td>
                <td>${attack}</td>
                <td><strong>${ip}</strong></td>
                <td>${score}</td>
                <td>
                    <button class="btn-danger" data-ip="${ip}">BLOCK</button>
                </td>
            `;

            const blockButton = row.querySelector('button[data-ip]');
            blockButton.addEventListener('click', () => blockIP(ip));

            tbody.appendChild(row);
        });
    }

    // Cập nhật các thẻ thống kê ở trên giao diện.
    const countCritical = document.getElementById('count-critical');
    const countHigh = document.getElementById('count-high');
    const countMedium = document.getElementById('count-medium');
    const countLow = document.getElementById('count-low');

    if (countCritical) countCritical.innerText = critical;
    if (countHigh) countHigh.innerText = high;
    if (countMedium) countMedium.innerText = medium;
    if (countLow) countLow.innerText = low;
}

/**
 * blockIP(ip)
 * Khi click nút BLOCK trên một cảnh báo, gửi yêu cầu POST /api/block.
 */
async function blockIP(ip) {
    if (!confirm('Xác nhận BLOCK IP: ' + ip + ' ?')) return;

    try {
        const result = await postJson('/block', { ip });
        alert(result.success ? '✅ ' + result.message : '❌ ' + result.message);
        loadAlerts();
    } catch (err) {
        alert('❌ Không thể kết nối Backend: ' + err.message);
    }
}

// Khởi chạy khi DOM đã sẵn sàng.
document.addEventListener('DOMContentLoaded', () => {
    loadAlerts();

    if (alertsIntervalId) clearInterval(alertsIntervalId);
    alertsIntervalId = setInterval(loadAlerts, 1000);
});

window.addEventListener('beforeunload', () => {
    if (alertsIntervalId) clearInterval(alertsIntervalId);
});