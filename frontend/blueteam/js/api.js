/**
 * api.js — MODULE GIAO TIẾP VỚI BACKEND (API LAYER)
 * 
 * Mục đích:
 * File này đóng vai trò trung gian giữa Frontend (FE) và Backend (BE).
 * Tất cả các request gọi đến server Java đều phải thông qua đây,
 * thay vì gọi trực tiếp ở nhiều file khác nhau.
 * 
 * Lợi ích:
 * - Dễ quản lý: chỉ cần sửa API_BASE khi đổi địa chỉ server
 * - Tái sử dụng: các file JS khác chỉ cần gọi lại hàm trong đây
 * - Dễ debug: tập trung xử lý lỗi API tại một nơi
 * - Có cơ chế fallback (mock data) khi backend chưa chạy
 */


/** 
 * ĐỊA CHỈ BACKEND (API SERVER)
 * Khi deploy thật (demo 2 máy), cần đổi localhost → IP máy Blue
 * Ví dụ: http://192.168.1.10:8080/api
 */
const API_BASE = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    ? `http://${window.location.hostname}:8080/api`
    : "http://172.21.214.96:8080/api";


/**
 * Hàm GET chung cho mọi endpoint.
 * Tạo URL, thêm _t để tránh cache browser, rồi fetch dữ liệu JSON.
 * Nếu có lỗi mạng / server chết, trả về dữ liệu mock để UI không crash.
 */
// fetchData là hàm GET dùng chung cho mọi màn hình.
// Nó tự thêm cache-busting và fallback dữ liệu giả khi backend không phản hồi.
async function fetchData(endpoint) {
    // Chuẩn hóa endpoint: đảm bảo luôn bắt đầu bằng '/'
    const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const url = `${API_BASE}${normalizedEndpoint}`;
    const noCacheUrl = `${url}${url.includes('?') ? '&' : '?'}_t=${Date.now()}`;

    try {
        const response = await fetch(noCacheUrl, { cache: 'no-store' });

        // Nếu backend trả lỗi HTTP như 404/500 thì ném lỗi để vào catch.
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status} - ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.warn(`[API] Không thể kết nối backend (${normalizedEndpoint}). Dùng mock data.`, error.message);
        return getMockData(normalizedEndpoint);
    }
}

/**
 * Hàm POST chung cho các thao tác như block/unblock.
 * Dùng để không lặp lại code fetch POST ở từng trang.
 */
async function postJson(endpoint, payload = {}) {
    const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;

    const response = await fetch(`${API_BASE}${normalizedEndpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || `HTTP Error: ${response.status}`);
    }

    return await response.json();
}

/**
 * Dữ liệu giả để test giao diện khi backend chưa chạy.
 * Mỗi endpoint sẽ trả một giá trị hợp lý để page không báo lỗi.
 */
function getMockData(endpoint) {
    if (endpoint === '/analyze') {
        return {
            status: 'analyzed',
            totalLogs: 0,
            riskAvg: 0
        };
    }

    if (endpoint === '/blocked') {
        return [];
    }

    if (endpoint === '/alerts') {
        return [];
    }

    return [];
}