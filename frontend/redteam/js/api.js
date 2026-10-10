/**
 * api.js — MODULE GIAO TIẾP VỚI BACKEND (DÀNH CHO RED TEAM)
 * 
 * Mục đích:
 * File này dùng để gửi các hành vi tấn công từ RedFE đến Backend.
 * Khác với BlueFE (chỉ đọc dữ liệu), RedFE sẽ gửi request dạng POST.
 * 
 * Chức năng chính:
 * - Gửi brute force attack
 * - Gửi request flood attack
 * - Kiểm tra trạng thái bị block
 */


/** Địa chỉ backend (đổi thành IP máy Blue khi demo 2 máy) */
const API_BASE = "http://172.21.214.96:8080/api";


/**
 * GỬI BRUTE FORCE ATTACK
 */
async function sendBruteForce() {
    const response = await fetch(`${API_BASE}/attack/bruteforce`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            action: "login_fail"
        })
    });

    if (response.status === 403) {
        window.location.href = "403.html";
        throw new Error("Blocked");//dừng luôn
    }
    return response.json();
}


/**
 * GỬI REQUEST FLOOD
 */
async function sendRequestFlood() {
    const response = await fetch(`${API_BASE}/attack/flood`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            action: "request_flood"
        })
    });

    if (response.status === 403) {
        window.location.href = "403.html";
        throw new Error("Blocked");//dừng luôn
    }
    return response.json();
}


/**
 * GỬI WEB PAYLOAD ATTACK (SQLi, XSS, Path Traversal, CMDi) ĐỂ AI PHÂN TÍCH
 */
async function sendWebPayload(payload) {
    const response = await fetch(`${API_BASE}/attack/payload`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ payload })
    });

    if (response.status === 403) {
        window.location.href = "403.html";
        throw new Error("Blocked");
    }
    return response.json();
}

/**
 * KIỂM TRA IP CÓ BỊ BLOCK KHÔNG
 */
async function checkBlock() {
    try {
        const response = await fetch(`${API_BASE}/check-block`);
        return await response.json();
    } catch (error) {
        console.error("Không check được block:", error);
        return { blocked: false };
    }
}