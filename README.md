# Hệ Thống Giám Sát An Ninh Mạng & Phòng Thủ Ứng Dụng Web Tích Hợp AI
### AI-Driven Hybrid NIDS & Web Application Firewall (WAF) System
> **Đề tài Nghiên cứu Khoa học (NCKH) / Đồ án Chuyên ngành Công nghệ Thông tin**

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![AI Engine](https://img.shields.io/badge/AI%20Models-XGBoost%20%7C%20TF--IDF%20%2B%20LogReg-orange.svg)](https://xgboost.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Giới Thiệu Tổng Quan

Dự án nghiên cứu và xây dựng giải pháp an ninh mạng toàn diện kết hợp giữa **Hệ thống Phát hiện Xâm nhập Mạng (NIDS)** và **Tường lửa Ứng dụng Web (WAF)** ứng dụng Trí tuệ Nhân tạo (Machine Learning).

Hệ thống hoạt động theo cơ chế **Hybrid (Luật Heuristic + Mô hình AI)**:
- Không chỉ dựa trên các ngưỡng số đếm tĩnh truyền thống (Rule-based), hệ thống được trang bị các mô hình AI đã huấn luyện trên các bộ dữ liệu an ninh mạng chuẩn quốc tế (**CICIDS2017**, **CSE-CIC-IDS2018**, **CSIC-2010 HTTP Dataset**).
- Tự động phân tích luồng mạng, bóc tách chuỗi payload HTTP theo thời gian thực (real-time), chấm điểm rủi ro (`risk_score`: 0–100) và tự động kích hoạt Tường lửa (Firewall) chặn (BLOCK) IP nguy hiểm khi điểm vượt ngưỡng an toàn.

---

## 🚀 Các Tính Năng Nổi Bật

### 1. Động Cơ AI Phát Hiện Tấn Công Đa Lớp
- **Phát hiện Xâm nhập Mạng (NIDS - Network Flow)**:
  - **Mô hình Nhị phân (XGBoost Binary)**: Phân biệt luồng dữ liệu an toàn (`Benign`) và luồng tấn công (`Attack`) dựa trên 77 đặc trưng chuẩn CICFlowMeter với độ chính xác **99.82%**.
  - **Mô hình Đa lớp (XGBoost Multiclass)**: Phân loại chi tiết 9 nhóm tấn công: `Benign`, `DDoS`, `DoS`, `BruteForce`, `Botnet`, `PortScan`, `Infiltration`, `Heartbleed`, `Web_Attack`.
- **Phát hiện Tấn công Web (WAF - Web Payload)**:
  - **Mô hình TF-IDF + Logistic Regression**: Bóc tách và phát hiện các mẫu tấn công ứng dụng Web phổ biến:
    - 💉 **SQL Injection (SQLi)** (Độ chính xác kiểm thử: ~83–99%)
    - 🎯 **Cross-Site Scripting (XSS)** (Độ chính xác: >99%)
    - 📁 **Path Traversal / Directory Browsing** (Độ chính xác: >99%)
    - ⚡ **Command Injection (CMDi)** (Độ chính xác: >99%)
    -  **Yêu cầu Hợp lệ (Normal/Norm)**

### 2. Động Cơ Phòng Thủ Tự Động (Hybrid Security Bot)
- Đánh giá đa chiều: Tần suất đăng nhập thất bại (`LOGIN_FAIL`), lưu lượng gửi yêu cầu (`REQUEST`), lịch sử vi phạm (`danger_history`), và điểm rủi ro AI (`AI Risk`).
- Tự động chuyển đổi 4 trạng thái giám sát IP: `PASS` (Bình thường) ➔ `SUSPICIOUS` (Nghi vấn) ➔ `MONITORING` (Theo dõi chặt) ➔ `BLOCKED` (Tường lửa chặn lập tức).
- Cơ chế Tường lửa thông minh: Chặn tự động khi rủi ro $\ge 45$ điểm hoặc cho phép chuyên viên can thiệp thủ công (Block/Unblock) qua giao diện.

### 3. Mô Hình Diễn Tập Đối Kháng (Blue Team vs Red Team)
- **Blue Team Dashboard (Trung tâm Phòng thủ)**:
  - Giám sát luồng Log thời gian thực.
  - Thống kê tỷ lệ các loại tấn công qua biểu đồ trực quan.
  - Quản lý danh sách cảnh báo (Alerts System) và danh sách IP bị Firewall cách ly.
- **Red Team Attack Tool (Công cụ Diễn tập Tấn công)**:
  - Mô phỏng tấn công Brute Force đăng nhập.
  - Mô phỏng tấn công Flood Request (DDoS/DoS).
  - **AI Web Payload Attack**: Công cụ thử nghiệm các biến thể mã độc Web với phản hồi trực tiếp từ AI.

---

## 📂 Cấu Trúc Thư Mục Dự Án

```
├── backend/                        # Máy chủ Backend (Python HTTP Server)
│   ├── alert/                      # Hệ thống cảnh báo an ninh (AlertSystem)
│   ├── core/                       # Động cơ an ninh cốt lõi
│   │   ├── ai_detector.py          # Module suy luận AI (Inference Engine)
│   │   ├── security_bot.py         # Bot an ninh Hybrid (Rule + AI)
│   │   ├── firewall.py             # Quản lý danh sách chặn IP
│   │   └── ip_profile.py           # Hồ sơ hành vi từng IP
│   ├── database/                   # Kết nối CSDL MySQL & DAO
│   │   ├── db.py                   # Quản lý Connection Pool & Fallback
│   │   └── log_dao.py              # Xử lý truy vấn logs & alerts
│   ├── models/                     # Data Models & AI Artifacts
│   │   ├── ai/                     # 4 file mô hình AI đã huấn luyện
│   │   │   ├── model_nids_binary.json
│   │   │   ├── model_nids_multiclass.json
│   │   │   ├── label_encoder_multiclass.pkl
│   │   │   └── model_web_payload.pkl
│   │   └── log_entry.py            # Đối tượng LogEntry chuẩn hóa
│   ├── services/                   # Các tiến trình nền
│   │   ├── log_analyzer.py         # Thống kê phân tích log
│   │   ├── log_reader.py           # Đọc file log mạng định dạng text
│   │   └── realtime_monitor.py     # Luồng quét định kỳ (Daemon thread)
│   ├── main.py                     # Điểm khởi chạy Backend & REST API
│   ├── requirements.txt            # Danh sách thư viện phụ thuộc
│   └── test_ai_inference.py        # Script kiểm thử độ chính xác các model AI
│
├── dataset/                        # Dữ liệu & Kịch bản huấn luyện AI
│   └── merge_datasets.py           # Tiền xử lý, trích xuất 77 đặc trưng luồng
│
└── frontend/                       # Giao diện người dùng (HTML5, CSS3, Vanilla JS)
    ├── dashboard.html              # Dashboard tổng quan (Blue Team)
    ├── monitor.html                # Giám sát nhật ký hoạt động thời gian thực
    ├── firewall.html               # Quản lý danh sách IP bị chặn
    ├── alerts.html                 # Danh sách cảnh báo an ninh chi tiết
    └── redteam FE/                 # Giao diện dành cho Red Team (Kẻ tấn công)
        ├── reddash.html            # Trang điều khiển Red Team
        ├── bruteforce.html         # Công cụ giả lập Brute Force
        ├── requestflood.html       # Công cụ giả lập Flooding
        ├── webattack.html          # Công cụ giả lập Payload Web (AI Test)
        └── 403.html                # Màn hình cảnh báo khi IP bị chặn
```

---

## ⚙️ Hướng Dẫn Cài Đặt & Khởi Chạy

### 1. Yêu Cầu Môi Trường
- **Python**: Phiên bản 3.10 trở lên.
- **MySQL**: (Tùy chọn) Nếu không cài MySQL, hệ thống sẽ tự động chuyển sang chế độ **File text fallback** (`logs/network.log`).

### 2. Cài Đặt Thư Viện
Mở terminal tại thư mục gốc của dự án và thực hiện:
```powershell
pip install -r backend/requirements.txt
```

### 3. Kiểm Thử Nhanh Các Mô Hình AI
Để kiểm tra độ chính xác và khả năng nhận diện của các mô hình AI với các mẫu tấn công thực tế:
```powershell
py backend/test_ai_inference.py
```

### 4. Khởi Động Máy Chủ Backend
```powershell
py backend/main.py
```
> Khi khởi động thành công, màn hình sẽ hiển thị:
> ```
> ============================================
>    AI Security IDS (Python) - Starting up
> ============================================
> [AIDetector] Nạp model_web_payload.pkl thành công! Nhãn: ['cmdi', 'norm', 'path-traversal', 'sqli', 'xss']
> [AIDetector] Nạp label_encoder_multiclass.pkl thành công!
> [AIDetector] Nạp model_nids_binary.json thành công!
> [AIDetector] Nạp model_nids_multiclass.json thành công!
>    SYSTEM READY: http://localhost:8080
> ============================================
> ```

### 5. Truy Cập Giao Diện Demo
Không cần cài đặt thêm web server, chỉ cần mở trực tiếp các file HTML bằng trình duyệt web bất kỳ:
- **Phòng thủ (Blue Team)**: Mở [`frontend/dashboard.html`](frontend/dashboard.html).
- **Tấn công thử nghiệm (Red Team)**: Mở [`frontend/redteam FE/reddash.html`](frontend/redteam%20FE/reddash.html).

---

## 📡 Danh Sách REST API

| Phương thức | Endpoint | Chức năng |
|:---|:---|:---|
| `GET` | `/api/analyze` | Lấy toàn bộ danh sách log và phân tích tổng quan |
| `GET` | `/api/alerts` | Lấy danh sách các cảnh báo an ninh |
| `GET` | `/api/blocked` | Lấy danh sách các IP đang bị Firewall chặn |
| `GET` | `/api/check-block` | Kiểm tra xem IP hiện tại có bị chặn hay không |
| `GET` | `/api/ai/status` | Xem thông tin trạng thái hoạt động của các Model AI |
| `POST` | `/api/ai/predict-payload` | Kiểm thử/dự đoán phân loại chuỗi payload web |
| `POST` | `/api/ai/predict-flow` | Dự đoán luồng mạng dựa trên 77 đặc trưng CICFlowMeter |
| `POST` | `/api/attack/payload` | Gửi payload tấn công từ Red Team (kích hoạt AI phân tích) |
| `POST` | `/api/attack/bruteforce` | Giả lập tấn công Brute Force đăng nhập |
| `POST` | `/api/attack/flood` | Giả lập tấn công Request Flood |
| `POST` | `/api/block` | Khóa thủ công một địa chỉ IP |
| `POST` | `/api/unblock` | Mở khóa (Unblock) một địa chỉ IP |

---

## 📜 Giấy Phép Bản Quyền (License)

Dự án được phát hành dưới giấy phép mã nguồn mở **[MIT License](LICENSE)**. Bạn hoàn toàn có quyền sử dụng, sửa đổi và phân phối phục vụ mục đích học tập và nghiên cứu.