/**
 * alerts.js — Hiển thị danh sách cảnh báo bảo mật.
 * Đọc dữ liệu từ /api/alerts (lấy từ bảng alerts trong DB).
 */

/**
 * HÀM LOAD CẢNH BÁO
 */
async function loadAlerts() {

    const alerts = await fetchData('/alerts');

    const tbody = document.getElementById("alerts-list-body");
    if (!tbody) return;
    if (!alerts || !Array.isArray(alerts)) return;

    tbody.innerHTML = "";

    // Đếm theo mức độ
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
            const level = alert.level || "LOW";
            const score = alert.score || 0;
            const time = alert.time || "-";
            const attack = alert.attack || "UNKNOWN";
            const ip = alert.ip || "N/A";

            if (level === "CRITICAL") critical++;
            else if (level === "HIGH") high++;
            else if (level === "MEDIUM") medium++;
            else low++;

            const severityClass = `severity-${level.toLowerCase()}`;

            const row = document.createElement("tr");
            row.innerHTML = `
                <td>${time}</td>
                <td class="${severityClass}">${level}</td>
                <td>${attack}</td>
                <td><strong>${ip}</strong></td>
                <td>${score}</td>
                <td>
                    <button class="btn-danger" onclick="blockIP('${ip}')">
                        BLOCK
                    </button>
                </td>
            `;

            tbody.appendChild(row);
        });
    }

    // Cập nhật counter cards
    const countCritical = document.getElementById("count-critical");
    const countHigh = document.getElementById("count-high");
    const countMedium = document.getElementById("count-medium");
    const countLow = document.getElementById("count-low");

    if (countCritical) countCritical.innerText = critical;
    if (countHigh) countHigh.innerText = high;
    if (countMedium) countMedium.innerText = medium;
    if (countLow) countLow.innerText = low;
}

/**
 * blockIP — Gọi API POST /api/block thật từ trang Alerts.
 * [FIX LỖI 12] Thay thế alert() placeholder
 */
async function blockIP(ip) {
    if (!confirm('Xác nhận BLOCK IP: ' + ip + ' ?')) return;
    try {
        // Dùng API_BASE từ api.js để nhất quán — không hardcode URL
        const response = await fetch(`${API_BASE}/block`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const result = await response.json();
        alert(result.success ? '✅ ' + result.message : '❌ ' + result.message);
    } catch (err) {
        alert('❌ Không thể kết nối Backend: ' + err.message);
    }
}

// 1s 1 lần
const alertsInterval = setInterval(loadAlerts, 1000);

document.addEventListener("DOMContentLoaded", loadAlerts);

window.addEventListener("beforeunload", () => clearInterval(alertsInterval));