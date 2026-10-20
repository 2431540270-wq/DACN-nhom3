/**
 * dashboard.js — Logic hoạt động chính của dashboard blue team.
 *
 * Vấn đề sửa ở đây:
 * 1. Thêm cleanup interval để tránh chạy lặp vô hạn khi chuyển trang.
 * 2. Tăng rõ ràng và dễ đọc khi render data dashboard.
 */

let dashboardIntervalId = null;

// loadLogs đọc dữ liệu tổng quan từ backend và hiển thị lên các card thống kê.
// Ngoài ra, nó lọc log đáng ngờ để hiển thị trong bảng "Hoạt động gần đây".
async function loadLogs() {
    try {
        const [stats, logs, blocked, alerts] = await Promise.all([
            fetchData('/analyze'),
            fetchData('/logs'),
            fetchData('/blocked'),
            fetchData('/alerts')
        ]);

        if (!stats || !logs || !blocked) {
            console.error('[Dashboard] Hệ thống lỗi — không nhận được Data. Xem lại Server!');
            return;
        }

        const statLogs = document.getElementById('stat-logs');
        if (statLogs) {
            statLogs.innerText = (stats.totalLogs || 0).toLocaleString();
        }

        let avgRisk = 0;
        if (stats.riskAvg !== undefined) {
            avgRisk = stats.riskAvg;
        } else if (logs.length > 0) {
            let totalRisk = 0;
            logs.forEach(l => { totalRisk += (l.score || 0); });
            avgRisk = Math.round(totalRisk / logs.length);
        }

        const statRisk = document.getElementById('stat-risk');
        if (statRisk) {
            statRisk.innerText = avgRisk;
        }

        const alertCount = Array.isArray(alerts) ? alerts.length : 0;
        const statAlerts = document.getElementById('stat-alerts');
        if (statAlerts) {
            statAlerts.innerText = alertCount;
        }

        let critCount = 0;
        let highCount = 0;
        let medCount = 0;
        if (Array.isArray(alerts)) {
            alerts.forEach(a => {
                const lvl = (a.level || '').toUpperCase();
                if (lvl === 'CRITICAL') critCount++;
                else if (lvl === 'HIGH') highCount++;
                else if (lvl === 'MEDIUM') medCount++;
            });
        }
        const elCrit = document.getElementById('dash-count-critical');
        if (elCrit) elCrit.innerText = critCount;
        const elHigh = document.getElementById('dash-count-high');
        if (elHigh) elHigh.innerText = highCount;
        const elMed = document.getElementById('dash-count-medium');
        if (elMed) elMed.innerText = medCount;

        const statBlocked = document.getElementById('stat-blocked');
        if (statBlocked) {
            statBlocked.innerText = blocked.length || 0;
        }

        const suspiciousLogs = Array.isArray(logs)
            ? logs.filter(log => log.status !== 'PASS' && log.status !== 'NORMAL').slice(0, 5)
            : [];

        const recentList = document.getElementById('recent-list');
        if (!recentList) return;

        recentList.innerHTML = '';

        if (suspiciousLogs.length === 0) {
            recentList.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">
                        Không có hoạt động đáng ngờ nào gần đây
                    </td>
                </tr>
            `;
            return;
        }

        suspiciousLogs.forEach(item => {
            const status = item.status || 'PASS';
            const ip = item.ip || 'N/A';
            const attack = item.attack || item.action || 'UNKNOWN';
            const score = item.score || 0;
            const time = item.time || '-';

            let severityClass = 'severity-low';
            if (status === 'BLOCKED') severityClass = 'severity-critical';
            else if (status === 'MONITORING') severityClass = 'severity-high';
            else if (status === 'SUSPICIOUS') severityClass = 'severity-medium';

            recentList.innerHTML += `
                <tr>
                    <td><strong>${ip}</strong></td>
                    <td>${time}</td>
                    <td>${attack}</td>
                    <td class="${severityClass}">${score}</td>
                    <td><span class="status-badge">${status}</span></td>
                </tr>
            `;
        });

    } catch (err) {
        console.error('[Dashboard] Load lỗi:', err);
    }
}

// Sau khi DOM sẵn sàng, ta load dữ liệu lần đầu và cập nhật định kỳ mỗi 1 giây.
// Việc clearInterval ở đây giúp tránh nhiều interval chạy chồng lên nhau khi chuyển trang.
document.addEventListener('DOMContentLoaded', () => {
    loadLogs();

    if (dashboardIntervalId) clearInterval(dashboardIntervalId);
    dashboardIntervalId = setInterval(() => {
        loadLogs();
    }, 1000);
});

window.addEventListener('beforeunload', () => {
    if (dashboardIntervalId) clearInterval(dashboardIntervalId);
});