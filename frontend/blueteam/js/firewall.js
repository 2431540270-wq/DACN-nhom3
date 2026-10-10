/**
 * firewall.js — ĐIỀU KHIỂN BẢNG BLOCK IP VÀ FORM CẤM IP THỦ CÔNG.
 *
 * [FIX LỖI 12] executeBlock() và unblock() giờ gọi API POST thật
 * [FIX LỖI 10] Thêm auto-refresh mỗi 5 giây
 */

/**
 * HÀM TẢI BẢNG LƯỚI TƯỜNG LỬA
 */
async function loadFirewall() {

    const blocked = await fetchData('/blocked');

    const tbody = document.getElementById('firewall-body');
    if (!tbody) return;
    if (!blocked || !Array.isArray(blocked)) return;

    tbody.innerHTML = '';

    if (blocked.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 30px;">
                    Không có IP nào bị chặn
                </td>
            </tr>
        `;
        return;
    }

    blocked.forEach(ip => {
        const tr = document.createElement("tr");
        const blockTime = new Date().toLocaleString('vi-VN');

        tr.innerHTML = `
        <td><strong>${ip}</strong></td>
        <td>${blockTime}</td>
        <td><span class="status-badge">Nghi ngờ tấn công mạng</span></td>
        <td>
            <button class="btn-success" onclick="unblock('${ip}')">
                GỠ CHẶN
            </button>
        </td>
        `;

        tbody.appendChild(tr);
    });
}

/**
 * executeBlock — Chặn IP thủ công, gọi API POST /api/block thật.
 * Thay thế alert() placeholder bằng fetch API thật
 */
async function executeBlock() {

    const input = document.getElementById('manual-ip');
    if (!input) return;

    const ip = input.value.trim();

    if (!ip) {
        alert('Địa chỉ IP không được để trống!');
        return;
    }

    const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (!ipRegex.test(ip)) {
        alert('Sai định dạng IPv4! Ví dụ đúng: 192.168.1.50');
        return;
    }

    // Kiểm tra từng octet 0-255
    const parts = ip.split('.').map(Number);
    if (parts.some(p => p < 0 || p > 255)) {
        alert('Một trong các octet của IP vượt ngoài phạm vi 0-255!');
        return;
    }

    try {
        const response = await fetch('http://172.21.214.96:8080/api/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const result = await response.json();
        if (result.success) {
            alert('✅ ' + result.message);
            input.value = '';
            loadFirewall(); // Làm mới bảng
        } else {
            alert('❌ Lỗi: ' + result.message);
        }
    } catch (err) {
        alert('❌ Không thể kết nối Backend: ' + err.message);
    }
}

/**
 * unblock — Gỡ chặn IP, gọi API POST /api/unblock thật.
 * [FIX LỖI 12] Thay thế alert() placeholder bằng fetch API thật
 */
async function unblock(ip) {
    if (!confirm('Xác nhận gỡ chặn IP: ' + ip + ' ?')) return;
    try {
        const response = await fetch('http://172.21.214.96:8080/api/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const result = await response.json();
        if (result.success) {
            alert('✅ ' + result.message);
            loadFirewall(); // Làm mới bảng
        } else {
            alert('❌ Lỗi: ' + result.message);
        }
    } catch (err) {
        alert('❌ Không thể kết nối Backend: ' + err.message);
    }
}

//Auto-refresh mỗi 1 giây
document.addEventListener('DOMContentLoaded', () => {
    loadFirewall();
    setInterval(loadFirewall, 1000);
});