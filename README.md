# Hệ Thống Phát Hiện Xâm Nhập Mạng Tích Hợp AI
### AI-Driven Network Intrusion Detection System (NIDS)
> **Đề tài Nghiên cứu Khoa học (NCKH) / Đồ án Chuyên ngành Công nghệ Thông tin**

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![AI Engine](https://img.shields.io/badge/AI%20Model-XGBoost%20Multiclass-orange.svg)](https://xgboost.readthedocs.io/)
[![Dataset](https://img.shields.io/badge/Dataset-CICIDS2017%20%7C%20CSE--CIC--IDS2018-green.svg)](https://www.unb.ca/cic/datasets/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Giới Thiệu Tổng Quan

Dự án nghiên cứu và xây dựng giải pháp **Hệ thống Phát hiện Xâm nhập Mạng (NIDS)** ứng dụng Machine Learning, tập trung vào ba nhóm mối đe dọa mạng phổ biến và nguy hiểm nhất:

- **DoS (Denial of Service)**: Tấn công từ chối dịch vụ từ một nguồn duy nhất (Hulk, GoldenEye, Slowloris, Slowhttptest).
- **DDoS (Distributed Denial of Service)**: Tấn công từ chối dịch vụ phân tán từ nhiều nguồn (LOIC, HOIC, DNS Flood).
- **PortScan**: Dò quét cổng dịch vụ nhằm thu thập thông tin mục tiêu (nmap SYN scan, UDP scan).

Hệ thống hoạt động theo cơ chế **Hybrid (Luật Heuristic + Mô hình AI)**:
- Phân tích luồng mạng theo thời gian thực (real-time) dựa trên **77 đặc trưng chuẩn CICFlowMeter**.
- Chấm điểm rủi ro (`risk_score`: 0–100) và tự động kích hoạt Tường lửa (Firewall) chặn IP nguy hiểm.
- Phân biệt **mức độ tự tin**: `HIGH` (≥ 85%) và `MEDIUM` (< 85%) để hỗ trợ quyết định phân tích viên.

---

## 🧠 Mô Hình AI

### Thuật toán sử dụng
| Thành phần | Thuật toán | Mô tả |
|:---|:---|:---|
| **NIDS Multiclass** | XGBoost (Extreme Gradient Boosting) | Phân loại trực tiếp 4 lớp: Benign / DoS / DDoS / PortScan |

### Chiến lược huấn luyện
- **Dữ liệu**: CICIDS2017 và CSE-CIC-IDS2018 — ~133.000 mẫu sau cân bằng.
- **Phương pháp**: Stratified 4-Fold Cross Validation với `sample_weight` để cân bằng lớp.
- **Chống học vẹt**: `max_depth=6`, `subsample=0.8`, `colsample_bytree=0.8`, `reg_alpha=0.1`, `reg_lambda=1.0`, Early Stopping (20 vòng không cải thiện).
- **Tăng tốc**: Huấn luyện trên GPU Kaggle (`tree_method=gpu_hist`).
- **Đánh giá**: Accuracy, Macro-F1, Log-Loss, Brier Score, Confusion Matrix.

### Kết quả Thực Nghiệm (Đánh giá trên tập dữ liệu chuẩn)
Hệ thống được kiểm thử bằng phương pháp **Stratified 4-Fold Cross Validation** trên GPU, tổng hợp từ file [`backend/models/ai/training_report.json`](backend/models/ai/training_report.json):

| Chỉ số đánh giá | Kết quả thực nghiệm | Ý nghĩa |
|:---|:---|:---|
| **Độ chính xác trung bình (Accuracy)** | **99.91%** (±0.016%) | Tỷ lệ nhận diện đúng tổng thể trên toàn bộ tập kiểm thử |
| **Macro-F1 Score** | **99.92%** (±0.015%) | Khả năng phát hiện cân bằng và đồng đều trên cả 4 lớp tấn công |
| **Log-Loss** | **0.0053** | Mức độ sai lệch xác suất dự đoán cực thấp, mô hình tự tin cao |
| **Brier Score** | **0.0004** | Độ hiệu chuẩn xác suất (probability calibration) tối ưu |
| **Tỷ lệ độ tự tin cao (High Confidence)** | **99.79%** | Đa số các mẫu dự đoán đều vượt ngưỡng tự tin 85% |
| **Độ chính xác nhóm High Confidence** | **99.95%** | Giảm thiểu tối đa tình trạng báo động giả (False Positive) |

*Phân bố mẫu huấn luyện (131.703 luồng)*: `Benign`: 38.034 | `DoS`: 40.000 | `DDoS`: 28.669 | `PortScan`: 25.000.  
Biểu đồ huấn luyện chi tiết được xuất tự động tại [`backend/models/ai/training_charts.png`](backend/models/ai/training_charts.png).

---

## 🚀 Các Tính Năng Nổi Bật

### 1. Động Cơ AI Phát Hiện Tấn Công Mạng (NIDS)
- **Mô hình XGBoost Multiclass**: Phân loại 4 nhóm dựa trên 77 đặc trưng CICFlowMeter.
- **Độ tự tin thực tế**: Mỗi dự đoán đi kèm phân phối xác suất đầy đủ 4 lớp.
- **Ngưỡng cảnh báo**: Điểm rủi ro từ 50–100, tự động chặn IP khi ≥ 45 điểm.

### 2. Động Cơ Phòng Thủ Tự Động (Hybrid Security Bot)
- Đánh giá đa chiều: Tần suất đăng nhập thất bại (`LOGIN_FAIL`), lưu lượng gửi yêu cầu (`REQUEST`), lịch sử vi phạm (`danger_history`), và điểm rủi ro AI.
- Tự động chuyển đổi 4 trạng thái: `PASS` ➔ `SUSPICIOUS` ➔ `MONITORING` ➔ `BLOCKED`.

### 3. Mô Hình Diễn Tập Đối Kháng (Blue Team vs Red Team)
- **Blue Team Dashboard**: Giám sát luồng log, thống kê tấn công, quản lý cảnh báo và IP bị chặn.
- **Red Team Tool**: Mô phỏng tấn công Brute Force, Flood Request (DDoS/DoS).

---

## 📂 Cấu Trúc Thư Mục Dự Án

```
├── backend/                        # Máy chủ Backend (Python HTTP Server)
│   ├── alert/                      # Hệ thống cảnh báo an ninh (AlertSystem)
│   ├── core/                       # Động cơ an ninh cốt lõi
│   │   ├── ai_detector.py          # Module suy luận AI (NIDS 4 lớp)
│   │   ├── security_bot.py         # Bot an ninh Hybrid (Rule + AI)
│   │   ├── firewall.py             # Quản lý danh sách chặn IP
│   │   └── ip_profile.py           # Hồ sơ hành vi từng IP
│   ├── database/                   # Kết nối CSDL MySQL & DAO
│   │   ├── db.py                   # Quản lý Connection Pool & Fallback
│   │   └── log_dao.py              # Xử lý truy vấn logs & alerts
│   ├── models/                     # Data Models & AI Artifacts
│   │   ├── ai/                     # Mô hình AI đã huấn luyện
│   │   │   ├── model_nids_multiclass.json       # XGBoost NIDS 4 lớp
│   │   │   ├── label_encoder_multiclass.pkl     # Bộ mã hóa nhãn
│   │   │   ├── training_charts.png              # Biểu đồ đánh giá huấn luyện
│   │   │   ├── training_report.json             # Báo cáo kết quả huấn luyện
│   │   │   └── README.txt                       # Hướng dẫn tải artifact AI
│   │   └── log_entry.py            # Đối tượng LogEntry chuẩn hóa
│   ├── services/                   # Các tiến trình nền
│   │   ├── log_analyzer.py         # Thống kê phân tích log
│   │   ├── log_reader.py           # Đọc file log mạng định dạng text
│   │   └── realtime_monitor.py     # Luồng quét định kỳ (Daemon thread)
│   ├── main.py                     # Điểm khởi chạy Backend & REST API
│   ├── requirements.txt            # Danh sách thư viện phụ thuộc
│   ├── test_ai_quick.py            # Script kiểm thử nhanh AIDetector
│   └── test_nids_focused.py        # Script kiểm thử NIDS 4 lớp (chuyên sâu)
│
├── dataset/                        # Dữ liệu & Kịch bản huấn luyện AI
│   ├── merge_datasets.py           # Tiền xử lý, trích xuất 77 đặc trưng luồng
│   └── processed/                  # Dữ liệu đã làm sạch và chuẩn hóa
│       ├── merged_cicids_network_flow.parquet   # Dữ liệu luồng mạng (24 MB)
│       ├── merged_cicids_network_flow.csv       # Phiên bản CSV (102 MB)
│       └── dataset_summary.json                 # Thống kê tổng quan dataset
│
├── frontend/                       # Giao diện người dùng (HTML5, CSS3, Vanilla JS)
│   ├── blueteam/                   # Giao diện dành cho Blue Team (Phòng thủ & Giám sát)
│   │   ├── index.html              # Trang đăng nhập demo
│   │   ├── dashboard.html          # Dashboard tổng quan
│   │   ├── monitor.html            # Giám sát nhật ký hoạt động thời gian thực
│   │   ├── firewall.html           # Quản lý danh sách IP bị chặn
│   │   ├── alerts.html             # Danh sách cảnh báo an ninh chi tiết
│   │   ├── attack-log.html         # Nhật ký các cuộc tấn công
│   │   ├── css/                    # Stylesheet cho Blue Team
│   │   └── js/                     # Logic kết nối API & render dữ liệu
│   └── redteam/                    # Giao diện dành cho Red Team (Tấn công mô phỏng)
│       ├── reddash.html            # Trang điều khiển Red Team
│       ├── bruteforce.html         # Công cụ giả lập Brute Force
│       ├── requestflood.html       # Công cụ giả lập Flooding (DoS/DDoS)
│       ├── webattack.html          # Công cụ tấn công Payload Web AI
│       ├── 403.html                # Màn hình cảnh báo khi IP bị chặn
│       ├── css/                    # Stylesheet cho Red Team
│       └── js/                     # Logic phát động tấn công qua API
│
├── nids_train_cells.py             # Các cell code để huấn luyện trên Kaggle
│
└── archive/                        # Lưu trữ các tệp cũ (không xóa)
    ├── web_payload/                # Model & dữ liệu WAF cũ (TF-IDF + LogReg)
    ├── java_bin/                   # Bytecode Java (.class) — phiên bản cũ
    ├── java_src/                   # Mã nguồn Java (.java) — phiên bản cũ
    └── java_meta/                  # Cấu hình Eclipse (.classpath, .project)
```

---

## ⚙️ Hướng Dẫn Cài Đặt & Khởi Chạy

### 1. Yêu Cầu Môi Trường
- **Python**: Phiên bản 3.10 trở lên.
- **MySQL**: (Tùy chọn) Nếu không cài MySQL, hệ thống tự động chuyển sang chế độ **File text fallback** (`logs/network.log`).

### 2. Cài Đặt Thư Viện
```powershell
pip install -r backend/requirements.txt
```

### 3. Đặt File Mô Hình AI Vào Đúng Vị Trí
Sau khi huấn luyện xong trên Kaggle, tải về và đặt vào thư mục `backend/models/ai/`:
```
backend/models/ai/
├── model_nids_multiclass.json        ← Tải từ Kaggle /kaggle/working/
├── label_encoder_multiclass.pkl      ← Tải từ Kaggle /kaggle/working/
├── training_report.json              ← Tải từ Kaggle /kaggle/working/
└── training_charts.png               ← (Tùy chọn) Tải từ Kaggle /kaggle/working/
```

### 4. Huấn Luyện Mô Hình Trên Kaggle
1. Vào [kaggle.com](https://kaggle.com) → **"New Notebook"** → chọn **Python**.
2. Vào **Settings** → **Accelerator** → chọn `GPU T4 x2`.
3. Upload file `dataset/processed/merged_cicids_network_flow.parquet` lên Kaggle Dataset.
4. Mở file [`nids_train_cells.py`](nids_train_cells.py) — copy từng khối code (từ `# %%` đến `# %%` tiếp theo) vào từng **Cell** của notebook.
5. **Sửa dòng `DATA_PATH`** trong Cell 2 cho đúng đường dẫn trên Kaggle:
   ```python
   DATA_PATH = "/kaggle/input/<tên-dataset-của-bạn>/merged_cicids_network_flow.parquet"
   ```
6. Chạy tuần tự từ Cell 1 → Cell 10.
7. Tải về các file artifact từ `/kaggle/working/` (xem Bước 3).

### 5. Kiểm Thử Mô Hình AI
```powershell
# Kiểm tra nhanh các hàm suy luận
py backend/test_ai_quick.py

# Kiểm thử chuyên sâu NIDS 4 lớp với các kịch bản thực tế
py backend/test_nids_focused.py
```
> Khi thành công, màn hình sẽ hiển thị kết quả 8 test case chi tiết kèm bảng phân phối xác suất và độ tự tin.

### 6. Khởi Động Máy Chủ Backend
```powershell
py backend/main.py
```
> Khi khởi động thành công:
> ```
> ============================================
>    AI Security IDS (Python) - Starting up
> ============================================
> [AIDetector] ✅ Nạp label_encoder_multiclass.pkl thành công! Nhãn: ['Benign', 'DDoS', 'DoS', 'PortScan']
> [AIDetector] ✅ Nạp model_nids_multiclass.json thành công!
> [AIDetector] ✅ Hệ thống NIDS sẵn sàng.
>    SYSTEM READY: http://localhost:8080
> ============================================
> ```

### 7. Truy Cập Giao Diện Demo
Không cần cài đặt thêm web server, mở trực tiếp bằng trình duyệt:
- **Phòng thủ (Blue Team)**: Mở [`frontend/blueteam/dashboard.html`](frontend/blueteam/dashboard.html) hoặc [`frontend/blueteam/index.html`](frontend/blueteam/index.html).
- **Tấn công thử nghiệm (Red Team)**: Mở [`frontend/redteam/reddash.html`](frontend/redteam/reddash.html).

---

## 📡 Danh Sách REST API

| Phương thức | Endpoint | Chức năng |
|:---|:---|:---|
| `GET` | `/api/analyze` | Lấy toàn bộ danh sách log và phân tích tổng quan |
| `GET` | `/api/alerts` | Lấy danh sách các cảnh báo an ninh |
| `GET` | `/api/blocked` | Lấy danh sách các IP đang bị Firewall chặn |
| `GET` | `/api/check-block` | Kiểm tra xem IP hiện tại có bị chặn hay không |
| `GET` | `/api/ai/status` | Xem thông tin trạng thái hoạt động của mô hình AI |
| `POST` | `/api/ai/predict-flow` | Dự đoán luồng mạng dựa trên 77 đặc trưng CICFlowMeter |
| `POST` | `/api/attack/bruteforce` | Giả lập tấn công Brute Force đăng nhập |
| `POST` | `/api/attack/flood` | Giả lập tấn công Request Flood (DoS/DDoS) |
| `POST` | `/api/block` | Khóa thủ công một địa chỉ IP |
| `POST` | `/api/unblock` | Mở khóa (Unblock) một địa chỉ IP |

---

## 🔮 Hướng Phát Triển Tương Lai (Future Work & Roadmap)

Để nâng cao khả năng ứng dụng thực tế và hoàn thiện đề tài NCKH, hệ thống định hướng mở rộng với các trọng tâm sau:

### 1. Thu Thập Lưu Lượng Mạng Tự Động Theo Thời Gian Thực (Automated Live Traffic Capture)
- **Bắt gói tin trực tiếp từ Card Mạng (NIC Sniffing)**:
  - Tích hợp module lắng nghe lưu lượng mạng trực tiếp từ interface mạng (ví dụ sử dụng `libpcap`, `PyShark`, `Scapy` hoặc `NFStream`).
  - Hệ thống tự động bắt các gói tin raw (Packet-level) mà không cần nhập dữ liệu thủ công hay phụ thuộc vào file log tạo sẵn.
- **Trích xuất đặc trưng luồng tự động (Automated Flow Extraction)**:
  - Gom các gói tin theo phiên kết nối 5-tuple (`Source IP`, `Source Port`, `Destination IP`, `Destination Port`, `Protocol`) thành các luồng mạng hai chiều (Bidirectional Network Flows).
  - Tự động tính toán tức thời **77 đặc trưng thống kê chuẩn CICFlowMeter** (như thời gian luồng, độ dài gói, khoảng cách giữa các gói - IAT, cờ TCP Flags, kích thước cửa sổ trượt Window Size,...) ngay trên luồng trực tiếp.
  - Chuyển tiếp ngay vector đặc trưng vào pipeline suy luận của `AIDetector` để cảnh báo và ngăn chặn trong thời gian thực với độ trễ tính bằng mili-giây (sub-second latency).

### 2. Tự Động Huấn Luyện Lại & Thích Ứng (Continuous & Active Learning)
- **Phát hiện trôi dạt dữ liệu (Concept Drift)**: Giám sát phân phối dữ liệu mạng thực tế để phát hiện khi các biến thể tấn công mới xuất hiện làm suy giảm hiệu suất mô hình.
- **Cơ chế Active Learning**: Tự động đánh dấu các luồng mạng có độ tự tin trung bình (`confidence < 85%`) hoặc điểm dị biệt cao để đưa vào hàng đợi xác thực của chuyên viên an ninh mạng.
- **Automated Retraining Pipeline**: Định kỳ tự động chuẩn hóa mẫu mới và tái huấn luyện mô hình XGBoost nhằm nâng cao khả năng phòng thủ trước các mối đe dọa Zero-day.

### 3. Tích Hợp Tường Lửa Hệ Điều Hành & Phần Cứng Mạng (IPS / Active Firewall Enforcement)
- **Tự động cấu hình Firewall cấp OS**: Mở rộng từ tường lửa ứng dụng (in-app firewall) sang thực thi lệnh chặn trực tiếp trên Tường lửa hệ điều hành:
  - **Linux**: Cập nhật rule thời gian thực qua `iptables` / `nftables` hoặc `ipset`.
  - **Windows**: Điều khiển `Windows Defender Firewall with Advanced Security` thông qua PowerShell API.
- **Hỗ trợ Mạng điều khiển bằng phần mềm (SDN/OpenFlow)**: Gửi lệnh điều khiển tới thiết bị Switch/Router để cô lập IP tấn công từ lớp mạng biên (Edge/Switch level).

### 4. Mở Rộng Phạm Vi Mối Đe Dọa & Tích Hợp SIEM/SOC
- Mở rộng tập dữ liệu và mô hình AI để nhận diện thêm các họ tấn công phức tạp khác như: **Botnet (Mirai, Ares)**, **Web Attack (SQL Injection, XSS, Path Traversal)**, và **Infiltration/Ransomware C2**.
- Xuất log cảnh báo theo định dạng chuẩn quốc tế (Syslog, CEF - Common Event Format, JSON streaming) để dễ dàng tích hợp vào các nền tảng SIEM/SOC phổ biến trong doanh nghiệp như **Wazuh, Splunk, Elastic SIEM**.

---

## 📜 Giấy Phép Bản Quyền (License)

Dự án được phát hành dưới giấy phép mã nguồn mở **[MIT License](LICENSE)**. Bạn hoàn toàn có quyền sử dụng, sửa đổi và phân phối phục vụ mục đích học tập và nghiên cứu.