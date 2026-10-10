/**
 * dashboard.js — Logic hoạt động ĐỘNG của thẻ HTML hiển thị Dashboard chính.
 * 
 * [FIX LỖI 9] stat-alerts bây giờ lấy từ /api/alerts thật thay vì filter từ /logs
 * [FIX LỖI 10] Tăng interval lên 5 giây để giảm tải backend
 */

async function loadLogs() {
    try {
        // BƯỚC 1: LẤY DỮ LIỆU (REAL-TIME)
        const [stats, logs, blocked, alerts] = await Promise.all([
            fetchData('/analyze'),
            fetchData('/logs'),
            fetchData('/blocked'),
            fetchData('/alerts')
        ]);

        if (!stats || !logs || !blocked) {
            console.error("[Dashboard] Hệ thống lỗi — không nhận được Data. Xem lại Server!");
            return;
        }

        // BƯỚC 2: HIỂN THỊ TỔNG LOG
        const statLogs = document.getElementById('stat-logs');
        if (statLogs) {
            statLogs.innerText = (stats.totalLogs || 0).toLocaleString();
        }

        // BƯỚC 3: TÍNH AVERAGE RISK
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

        // BƯỚC 4: ĐẾM SỐ CẢNH BÁO THẬT TỪ /api/alerts
        // [FIX LỖI 9] Dùng alerts từ /api/alerts thay vì filter status=SUSPICIOUS từ /logs
        const alertCount = Array.isArray(alerts) ? alerts.length : 0;
        const statAlerts = document.getElementById('stat-alerts');
        if (statAlerts) {
            statAlerts.innerText = alertCount;
        }

        // BƯỚC 5: ĐẾM IP ĐÃ CHẶN
        const statBlocked = document.getElementById('stat-blocked');
        if (statBlocked) {
            statBlocked.innerText = blocked.length || 0;
        }

        // BƯỚC 6: RENDER BẢNG HOẠT ĐỘNG GẦN ĐÂY
        // Lọc log nguy hiểm (không phải PASS và không phải NORMAL) để hiển thị
        const suspiciousLogs = Array.isArray(logs)
            ? logs.filter(log => log.status !== 'PASS').slice(0, 5)
            : [];

        const recentList = document.getElementById('recent-list');
        if (!recentList) return;

        recentList.innerHTML = "";

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
            const attack = item.attack || item.action || 'UNKNOWN'; // API trả về "attack", fallback action
            const score = item.score || 0;
            const time = item.time || '-';

            // Map status → severity class
            let severityClass = 'severity-low';
            if (status === 'BLOCKED') severityClass = 'severity-critical';
            else if (status === 'MONITORING') severityClass = 'severity-high';
            else if (status === 'SUSPICIOUS') severityClass = 'severity-medium';

            const row = `
            <tr>
                <td><strong>${ip}</strong></td>
                <td>${time}</td>
                <td>${attack}</td>
                <td class="${severityClass}">${score}</td>
                <td>
                    <span class="status-badge">${status}</span>
                </td>
            </tr>
            `;

            recentList.innerHTML += row;
        });

    } catch (err) {
        console.error("[Dashboard] Load lỗi:", err);
    }
}

// Gọi ngay khi load trang
document.addEventListener('DOMContentLoaded', () => {
    loadLogs();

    // /analyze phải chạy SecurityBot.analyze() + DB read mỗi lần gọi
    setInterval(() => {
        loadLogs();
    }, 1000);
});