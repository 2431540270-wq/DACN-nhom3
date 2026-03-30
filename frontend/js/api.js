/**
 * api.js — MODULE KẾT NỐI API / LÕI GIAO TIẾP VỚI BACKEND.
 * 
 * Mục đích:
 * Mọi file Javascript khác (dashboard.js, alerts.js) khi muốn xin dữ liệu từ Server Java
 * thì đều KHÔNG được phép gọi chay, mà phải NHỜ VẢ QUA FILE NÀY.
 * 
 * Lợi ích của việc tách Lõi: 
 * Lỡ như link thư viện dời vị trí, bạn chỉ cần vào đây sửa `API_BASE` thay vì lục lại hàng chục file.
 * Ngoài ra, nếu JAVA TẮT MÁY, file này có "Sức Rập" (Mock Data) giả vờ sinh ra dữ liệu mẫu để bạn test giao diện!
 */

/** BIẾN TOÀN CỤC: Địa chỉ cái cửa (số cổng) của gã lễ tân Java ApiServer.java (Nhớ bật backend!). */
const API_BASE = "http://localhost:8080/api";

/**
 * HÀM CỐT LÕI: fetchData(endpoint) 
 * 
 * Giải Cứu Newbie: (ASYNC / AWAIT) => Khi gửi lệnh cho Java phải qua mạng tốn mất nửa giây.
 * Trình duyệt KHÔNG MUỐN BỊ CHỜ ĐỢI (Đứng hình web) -> Sinh ra cơ chế "Đợi chút" (Await).
 * Javascript sẽ vứt cái yêu cầu kia lên mây tự chờ, trong lúc đó nó vẽ hình cho bạn bấm tiếp, lúc nào kết quả về, nó chạy lại dòng đó mượt mà!
 *
 * @param {string} endpoint - Tên API muốn gọi (Cắt nhỏ cái đuôi ra. Vd: "/logs" hoặc "/analyze")
 * @returns {Promise<Object|Array>} Nếu chờ Mạng về thành công thì đưa ra gói Array JSON.
 */
async function fetchData(endpoint) {
    try {
        // fetch là khẩu súng gọi API có sẵn trong Javascript. Ghép chuỗi base và endpoint vào thành nòng súng.
        // Khắc phục Vấn Đề 5: Thêm ?_t= (timestamp) để luôn fetch dữ liệu mới, không dùng cache
        const url = `${API_BASE}${endpoint}`;
        const noCacheUrl = url.includes('?') ? `${url}&_t=${Date.now()}` : `${url}?_t=${Date.now()}`;
        const response = await fetch(noCacheUrl, { cache: 'no-store' });

        // Lỡ Backend trả về mã tạch, ví dụ File Bị Lỗi (Mã 500), hoặc không tìm thấy (Mã 404)
        if (!response.ok) {
            // Nem cái Lỗi to đùng để thằng "CATCH" chạy vội tới xử lý giùm!
            throw new Error(`Trầm Vả! Lỗi HTTP Gòi Xếp! Mã Xấu: ${response.status}: ${response.statusText}`);
        }

        // Đợi Java chuyển Chuỗi Gói hàng Text sang Object Javascript chuẩn (Dễ thao tác biến) rồi bốc.
        return await response.json();

    } catch (error) {

        // Lọt vào đây là do 2 trường hợp: Bị ném lỗi do 404/500 ở trên, HOẶC CHƯA BẬT JAVA BACKEND.
        console.warn(`[API] Này Bạn Giảng Viên à, Backend Tắt Rồi Nhé (${endpoint}). Tôi Bật Fake Data Mẫu Vào Nhé!`, error.message);

        // Fake data để gánh vội điểm demo.
        return getMockData(endpoint);
    }
}

/**
 * HÀM DỰ PHÒNG: getMockData (HỘP GIẢ DỮ LIỆU)
 * Khi fetch "tắt thở lạc mất tiêu", trả dòng MockData này.
 *
 * @param {string} endpoint - Hỏi tên đường Link để giả bộ chập chứng đúng bài Data yêu cầu ở Java
 */
function getMockData(endpoint) {

    // Sinh thời gian hiện tại
    const now = new Date().toLocaleTimeString();

    // 1. Phân Tích Cơ Bản
    if (endpoint === '/analyze') {
        return { status: "analyzed", totalLogs: 0, riskAvg: 0 };
    }

    return [];
}