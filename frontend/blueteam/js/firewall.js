/**
 * firewall.js — Quản lý danh sách IP bị chặn và thao tác block/unblock.
 *
 * Mục tiêu của file này:
 * - Lấy danh sách IP đang bị chặn từ backend
 * - Chặn IP thủ công qua form trên giao diện
 * - Gỡ chặn IP khi đã xác định an toàn
 * - Refresh dữ liệu định kỳ để dashboard luôn cập nhật
 */

// Biến lưu interval để dọn khi rời trang hoặc reload lại.
let firewallIntervalId = null;

/**
 * loadFirewall()
 * Gọi /api/blocked để lấy danh sách IP đang bị chặn.
 * Sau đó render vào tbody của bảng trên firewall.html.
 */
// loadFirewall đọc danh sách IP bị chặn từ backend và render vào bảng quản lý Firewall.
// Nếu danh sách rỗng, hiển thị một dòng thông báo thay vì bảng trống.
async function loadFirewall() {
    const blocked = await fetchData('/blocked');
    const tbody = document.getElementById('firewall-body');

    if (!tbody) return;
    if (!Array.isArray(blocked)) return;

    tbody.innerHTML = '';

    // Nếu không có IP nào bị chặn thì hiện một dòng thông báo.
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
            <button class="btn-success" data-ip="${ip}">
                GỠ CHẶN
            </button>
        </td>
        `;

        const actionButton = tr.querySelector('button[data-ip]');
        if (actionButton) {
            actionButton.addEventListener('click', () => unblock(ip));
        }

        tbody.appendChild(tr);
    });
}

/**
 * executeBlock()
 * Xử lý khi người dùng nhập IP và nhấn nút "THỰC THI CHẶN".
 * Kiểm tra định dạng IP rồi gửi POST /api/block lên backend.
 */
// executeBlock xử lý việc người dùng nhập IP thủ công và yêu cầu chặn.
// Ở đây ta validate định dạng IPv4 để tránh gửi dữ liệu không hợp lệ lên backend.
async function executeBlock() {
    const input = document.getElementById('manual-ip');
    if (!input) return;

    const ip = input.value.trim();
    const reasonDropdown = document.getElementById('manual-reason');
    const reason = reasonDropdown ? reasonDropdown.value : 'Manual Block';

    // 1. Không cho phép để trống.
    if (!ip) {
        alert('Địa chỉ IP không được để trống!');
        return;
    }

    // 2. Validate IPv4 theo chuẩn 4 octet.
    const ipRegex = /^\d{1,3}(?:\.\d{1,3}){3}$/;
    if (!ipRegex.test(ip)) {
        alert('Sai định dạng IPv4! Ví dụ đúng: 192.168.1.50');
        return;
    }

    // 3. Kiểm tra từng octet nằm trong khoảng 0-255.
    const parts = ip.split('.').map(Number);
    if (parts.some(part => part < 0 || part > 255)) {
        alert('Một trong các octet của IP vượt ngoài phạm vi 0-255!');
        return;
    }

    try {
        const result = await postJson('/block', { ip: ip });
        if (result.success) {
            alert('✅ ' + result.message);
            input.value = '';
            loadFirewall();
        } else {
            alert('❌ Lỗi: ' + (result.message || 'Không thể chặn IP'));
        }
    } catch (err) {
        alert('❌ Không thể kết nối Backend: ' + err.message);
    }
}

/**
 * unblock(ip)
 * Gỡ chặn IP khi admin xác nhận.
 */
async function unblock(ip) {
    if (!confirm('Xác nhận gỡ chặn IP: ' + ip + ' ?')) return;

    try {
        const result = await postJson('/unblock', { ip: ip });
        if (result.success) {
            alert('✅ ' + result.message);
            loadFirewall();
        } else {
            alert('❌ Lỗi: ' + (result.message || 'Không thể gỡ chặn'));
        }
    } catch (err) {
        alert('❌ Không thể kết nối Backend: ' + err.message);
    }
}

// Khởi chạy khi DOM sẵn sàng.
// Tự động load dữ liệu lần đầu và refresh mỗi 1 giây.
document.addEventListener('DOMContentLoaded', () => {
    loadFirewall();

    if (firewallIntervalId) clearInterval(firewallIntervalId);
    firewallIntervalId = setInterval(loadFirewall, 1000);
});

// Dọn interval khi rời trang để tránh memory leak.
window.addEventListener('beforeunload', () => {
    if (firewallIntervalId) clearInterval(firewallIntervalId);
});