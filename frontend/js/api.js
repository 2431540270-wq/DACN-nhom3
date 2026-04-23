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
const API_BASE = "http://172.21.214.96:8080/api";


/**
 * HÀM CHÍNH: fetchData(endpoint)
 * 
 * Chức năng:
 * Gửi request GET đến backend và trả về dữ liệu JSON.
 * 
 * Cơ chế async/await:
 * - Gửi request bất đồng bộ (không làm đứng giao diện)
 * - Chờ server phản hồi rồi xử lý tiếp
 * 
 * @param {string} endpoint - Đường dẫn API (vd: "/logs", "/analyze")
 * @returns {Promise<Object|Array>} Dữ liệu JSON trả về từ server
 */
async function fetchData(endpoint) {
    try {
        // Tạo URL hoàn chỉnh
        const url = `${API_BASE}${endpoint}`;

        // Thêm timestamp để tránh cache (luôn lấy dữ liệu mới)
        const noCacheUrl = url.includes('?')
            ? `${url}&_t=${Date.now()}`
            : `${url}?_t=${Date.now()}`;

        // Gửi request
        const response = await fetch(noCacheUrl, { cache: 'no-store' });

        // Kiểm tra lỗi HTTP (404, 500,...)
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status} - ${response.statusText}`);
        }

        // Parse JSON từ response
        return await response.json();

    } catch (error) {

        // Trường hợp lỗi:
        // - Backend chưa chạy
        // - Sai endpoint
        // - Lỗi server
        console.warn(`[API] Không thể kết nối backend (${endpoint}). Sử dụng mock data.`, error.message);

        // Trả dữ liệu giả để không crash UI
        return getMockData(endpoint);
    }
}


/**
 * HÀM DỰ PHÒNG: getMockData(endpoint)
 * 
 * Chức năng:
 * Trả dữ liệu giả khi backend không hoạt động,
 * giúp frontend vẫn chạy để test giao diện.
 * 
 * @param {string} endpoint - Endpoint cần giả lập dữ liệu
 */
function getMockData(endpoint) {

    const now = new Date().toLocaleTimeString();

    // Ví dụ dữ liệu cho endpoint /analyze
    if (endpoint === '/analyze') {
        return {
            status: "analyzed",
            totalLogs: 0,
            riskAvg: 0
        };
    }

    // Mặc định trả mảng rỗng
    return [];
}