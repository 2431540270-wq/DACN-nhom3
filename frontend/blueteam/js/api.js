/**
 * api.js — File trung tâm để frontend blue team gọi backend.
 *
 * Ý tưởng của file này:
 * - Tất cả request API đều đi qua đây để tránh lặp lại URL ở nhiều chỗ.
 * - Khi backend chưa chạy, UI vẫn có dữ liệu giả để demo không bị lỗi.
 * - Một khi đổi server, chỉ cần sửa 1 chỗ: API_BASE.
 */

// Khởi tạo URL gốc của backend.
// Nếu đang chạy local thì dùng localhost:8080/api,
// nếu đang chạy trên server thật thì có thể dùng IP cố định.
// API_BASE quyết định địa chỉ backend mà frontend sẽ gọi.
// Nếu đang chạy local, ta nối tới localhost:8080; nếu chạy trên server thật, dùng IP cố định.
const API_BASE = (() => {
    const hostname = window.location.hostname;
    const protocol = window.location.protocol === 'file:' ? 'http:' : window.location.protocol;
    const isLocalhost = ['localhost', '127.0.0.1', '::1'].includes(hostname);

    if (isLocalhost) {
        return `${protocol}//${hostname}:8080/api`;
    }

    return 'http://172.21.214.96:8080/api';
})();

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