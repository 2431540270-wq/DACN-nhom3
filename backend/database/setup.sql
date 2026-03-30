-- ============================================================
-- SQL SCRIPT: Thiết lập Database cho hệ thống AI Security IDS
-- ============================================================
-- Cách chạy:
--   1. Mở MySQL Workbench
--   2. Kết nối vào MySQL Server (localhost:3306)
--   3. Mở file này hoặc copy-paste vào Query Editor
--   4. Nhấn nút ⚡ (Execute) để chạy toàn bộ
-- ============================================================

-- 1. TẠO DATABASE
-- Nếu đã tồn tại thì bỏ qua (IF NOT EXISTS)
CREATE DATABASE IF NOT EXISTS security_logs
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

-- 2. CHỌN DATABASE ĐỂ LÀM VIỆC
USE security_logs;

-- 3. TẠO BẢNG LOGS
-- Bảng này lưu toàn bộ log mạng mà hệ thống ghi nhận
CREATE TABLE IF NOT EXISTS logs (
    -- ID tự tăng (mỗi bản ghi có 1 số duy nhất)
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Thời gian ghi nhận log (tự động lấy giờ hiện tại nếu không truyền)
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Địa chỉ IP nguồn (ai đang truy cập)
    ip_address VARCHAR(50) NOT NULL,

    -- Hành động: LOGIN_FAIL, LOGIN_SUCCESS, REQUEST
    action VARCHAR(100) NOT NULL,

    -- Trạng thái sau phân tích AI: PASS, SUSPICIOUS, MONITORING, BLOCKED
    status VARCHAR(50) DEFAULT 'PASS',

    -- Loại tấn công: NORMAL, BRUTE_FORCE, REQUEST_FLOOD
    attack_type VARCHAR(50) DEFAULT 'NORMAL',

    -- Mô tả chi tiết (tùy chọn)
    description TEXT
);

-- 4. TẠO INDEX ĐỂ TÌM KIẾM NHANH
-- Index giống như Mục lục sách: tìm theo IP hoặc thời gian sẽ nhanh hơn rất nhiều
CREATE INDEX IF NOT EXISTS idx_ip   ON logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_time ON logs(timestamp);

-- 5. CHÈN DỮ LIỆU MẪU ĐỂ TEST
-- 10 dòng log mô phỏng các tình huống tấn công khác nhau
INSERT INTO logs (timestamp, ip_address, action, status, attack_type, description) VALUES
    ('2026-03-26 08:00:01', '192.168.1.15', 'LOGIN_FAIL', 'BLOCKED',     'BRUTE_FORCE',    'Dò mật khẩu liên tục - đã bị chặn bởi AI'),
    ('2026-03-26 08:00:02', '192.168.1.15', 'LOGIN_FAIL', 'BLOCKED',     'BRUTE_FORCE',    'Tiếp tục dò mật khẩu sau khi bị cảnh báo'),
    ('2026-03-26 08:00:03', '192.168.1.15', 'LOGIN_FAIL', 'BLOCKED',     'BRUTE_FORCE',    'Lần thứ 3 thất bại - xác nhận Brute Force'),
    ('2026-03-26 08:01:00', '10.0.0.50',   'REQUEST',    'MONITORING',  'REQUEST_FLOOD',  'Gửi quá nhiều request trong 1 phút'),
    ('2026-03-26 08:01:30', '10.0.0.50',   'REQUEST',    'MONITORING',  'REQUEST_FLOOD',  'Tiếp tục flood request - đang theo dõi'),
    ('2026-03-26 08:02:00', '8.8.8.8',     'LOGIN_SUCCESS','PASS',       'NORMAL',         'Đăng nhập thành công - người dùng hợp lệ'),
    ('2026-03-26 08:02:30', '8.8.8.8',     'REQUEST',    'PASS',        'NORMAL',         'Truy vấn dữ liệu bình thường'),
    ('2026-03-26 08:03:00', '172.16.0.4',  'LOGIN_FAIL', 'SUSPICIOUS',  'NORMAL',         'Nhập sai mật khẩu 1 lần - chưa đáng ngại'),
    ('2026-03-26 08:03:30', '172.16.0.4',  'LOGIN_FAIL', 'SUSPICIOUS',  'NORMAL',         'Nhập sai mật khẩu lần 2 - bắt đầu nghi ngờ'),
    ('2026-03-26 08:04:00', '103.45.12.7', 'LOGIN_FAIL', 'BLOCKED',     'BRUTE_FORCE',    'IP từ nước ngoài - đã chặn ngay');

-- 6. KIỂM TRA KẾT QUẢ
-- Chạy lệnh này để xem dữ liệu đã chèn thành công chưa
SELECT * FROM logs ORDER BY timestamp DESC;

-- ============================================================
-- XONG! Database đã sẵn sàng. Tiếp theo:
--   1. Thêm MySQL JDBC Driver vào project Java
--   2. Chạy Main.java → Backend sẽ kết nối DB tự động
-- ============================================================