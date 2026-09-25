"""
test_nids_focused.py
─────────────────────────────────────────────────────────────────────────────
Kiểm thử suy luận mô hình NIDS tập trung vào 4 nhóm tấn công:
    Benign / DoS / DDoS / PortScan

Cách chạy (từ thư mục gốc dự án):
    py backend/test_nids_focused.py
─────────────────────────────────────────────────────────────────────────────
"""

import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Thêm thư mục backend vào sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from core.ai_detector import AIDetector


# ─────────────────────────────────────────────────────────────────────────────
# CÁC MẪU LUỒNG MẠNG KIỂM THỬ (vector 77 đặc trưng CICFlowMeter)
# Vị trí các đặc trưng quan trọng (0-indexed):
#   Index 0  = Protocol
#   Index 1  = Flow Duration
#   Index 2  = Total Fwd Packets
#   Index 3  = Total Backward Packets
#   Index 15 = Flow Packets/s
#   Index 44 = SYN Flag Count
#   Index 46 = RST Flag Count
#   Index 48 = ACK Flag Count
# ─────────────────────────────────────────────────────────────────────────────

FEATURE_COLS = [
    "Protocol",
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total",
    "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Packet Length Min", "Packet Length Max",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Avg Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init Fwd Win Bytes", "Init Bwd Win Bytes",
    "Fwd Act Data Packets", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

COL_INDEX = {col: i for i, col in enumerate(FEATURE_COLS)}


def make_flow_from_dict(d: dict) -> list:
    """Tạo vector 77 đặc trưng dựa trên dict tên cột."""
    v = [0.0] * len(FEATURE_COLS)
    for col_name, val in d.items():
        if col_name in COL_INDEX:
            v[COL_INDEX[col_name]] = float(val)
    return v


# Định nghĩa các mẫu kiểm thử đặc trưng chuẩn CICIDS2017
TEST_CASES = [
    {
        "name": "Lưu lượng HTTPS bình thường (Benign)",
        "expected": "Benign",
        "flow": make_flow_from_dict({
            "Protocol": 6, "Flow Duration": 150000,
            "Total Fwd Packets": 10, "Total Backward Packets": 9,
            "Fwd Packets Length Total": 3200, "Bwd Packets Length Total": 4800,
            "Fwd Packet Length Max": 1460, "Fwd Packet Length Min": 0, "Fwd Packet Length Mean": 320,
            "Bwd Packet Length Max": 1460, "Bwd Packet Length Min": 52, "Bwd Packet Length Mean": 533,
            "Flow Bytes/s": 53333.3, "Flow Packets/s": 126.6,
            "Fwd Header Length": 200, "Bwd Header Length": 180,
            "Fwd Packets/s": 66.6, "Bwd Packets/s": 60.0,
            "Packet Length Min": 0, "Packet Length Max": 1460, "Packet Length Mean": 421.0,
            "ACK Flag Count": 1, "Avg Packet Size": 443.0,
            "Init Fwd Win Bytes": 8192, "Init Bwd Win Bytes": 8192,
            "Fwd Act Data Packets": 3, "Fwd Seg Size Min": 20,
        }),
    },
    {
        "name": "HTTP GET thông thường (Benign)",
        "expected": "Benign",
        "flow": make_flow_from_dict({
            "Protocol": 6, "Flow Duration": 85000,
            "Total Fwd Packets": 5, "Total Backward Packets": 4,
            "Fwd Packets Length Total": 450, "Bwd Packets Length Total": 3200,
            "Fwd Packet Length Max": 450, "Fwd Packet Length Min": 0, "Fwd Packet Length Mean": 90,
            "Bwd Packet Length Max": 1460, "Bwd Packet Length Min": 52, "Bwd Packet Length Mean": 800,
            "Flow Bytes/s": 42941.1, "Flow Packets/s": 105.8,
            "Fwd Header Length": 100, "Bwd Header Length": 80,
            "Bwd Packets/s": 47.0, "Packet Length Min": 0, "Packet Length Mean": 405.0,
            "ACK Flag Count": 1, "Init Fwd Win Bytes": 29200, "Init Bwd Win Bytes": 28960,
            "Fwd Seg Size Min": 20,
        }),
    },
    {
        "name": "SYN Flood — DDoS điển hình",
        "expected": "DDoS",
        "flow": make_flow_from_dict({
            "Protocol": 6, "Flow Duration": 120,
            "Total Fwd Packets": 3, "Total Backward Packets": 0,
            "Fwd Packets Length Total": 0, "Bwd Packets Length Total": 0,
            "Fwd Packet Length Max": 0, "Fwd Packet Length Min": 0,
            "Bwd Packet Length Max": 0, "Bwd Packet Length Min": 0,
            "Flow Bytes/s": 0.0, "Flow Packets/s": 25000.0,
            "Fwd Header Length": 96, "Bwd Header Length": 0,
            "Fwd Packets/s": 25000.0, "Bwd Packets/s": 0.0,
            "SYN Flag Count": 1, "ACK Flag Count": 0,
            "Init Fwd Win Bytes": 256, "Init Bwd Win Bytes": -1,
            "Fwd Seg Size Min": 32, "Subflow Fwd Packets": 3, "Subflow Bwd Packets": 0,
        }),
    },
    {
        "name": "HTTP Flood / LOIC — DDoS tầng ứng dụng",
        "expected": "DDoS",
        "flow": make_flow_from_dict({
            "Protocol": 6, "Flow Duration": 5000,
            "Total Fwd Packets": 4, "Total Backward Packets": 0,
            "Fwd Packets Length Total": 0, "Bwd Packets Length Total": 0,
            "Bwd Packet Length Min": 0, "Bwd Packets/s": 0,
            "SYN Flag Count": 1, "ACK Flag Count": 0,
            "Init Fwd Win Bytes": 256, "Init Bwd Win Bytes": -1,
            "Fwd Seg Size Min": 32, "Subflow Fwd Packets": 4,
        }),
    },
    {
        "name": "DoS Hulk — Flood lượng lớn request HTTP",
        "expected": "DoS",
        "flow": make_flow_from_dict({
            "Protocol": 6, "Flow Duration": 1200000,
            "Total Fwd Packets": 6, "Total Backward Packets": 6,
            "Fwd Packets Length Total": 1800, "Bwd Packets Length Total": 12000,
            "Fwd Packet Length Max": 350, "Fwd Packet Length Min": 0,
            "Bwd Packet Length Max": 4000, "Bwd Packet Length Min": 0,
            "Fwd Header Length": 192, "Bwd Header Length": 200,
            "Bwd Packet Length Std": 1200.0,
            "Fwd Packets/s": 5.0, "Bwd Packets/s": 5.0,
            "ACK Flag Count": 1, "RST Flag Count": 1,
            "Init Fwd Win Bytes": 29200, "Init Bwd Win Bytes": 235,
            "Fwd Seg Size Min": 32, "Idle Mean": 800000, "Idle Max": 900000,
        }),
    },
    {
        "name": "DoS Slowloris — Giữ kết nối kéo dài",
        "expected": "DoS",
        "flow": make_flow_from_dict({
            "Protocol": 6, "Flow Duration": 75000000,
            "Total Fwd Packets": 8, "Total Backward Packets": 4,
            "Fwd Packets Length Total": 700, "Bwd Packets Length Total": 150,
            "Fwd Packet Length Max": 150, "Bwd Packet Length Min": 0,
            "Flow Packets/s": 0.16, "Bwd Packets/s": 0.05,
            "Fwd Header Length": 260, "Bwd Header Length": 130,
            "Init Fwd Win Bytes": 29200, "Init Bwd Win Bytes": 235,
            "Fwd Seg Size Min": 32,
            "Idle Mean": 15000000, "Idle Max": 20000000, "Idle Min": 10000000,
        }),
    },
    {
        "name": "Dò quét cổng SYN Scan (PortScan)",
        "expected": "PortScan",
        "flow": make_flow_from_dict({
            "Protocol": 6, "Flow Duration": 25,
            "Total Fwd Packets": 1, "Total Backward Packets": 1,
            "Fwd Packets Length Total": 0, "Bwd Packets Length Total": 0,
            "Fwd Packet Length Max": 0, "Bwd Packet Length Min": 0,
            "Fwd Header Length": 24, "Bwd Header Length": 20,
            "SYN Flag Count": 1, "RST Flag Count": 1,
            "Fwd Packets/s": 40000.0, "Bwd Packets/s": 40000.0,
            "Init Fwd Win Bytes": 1024, "Init Bwd Win Bytes": 0,
            "Fwd Seg Size Min": 24,
        }),
    },
    {
        "name": "Dò quét cổng Nmap Stealth (PortScan)",
        "expected": "PortScan",
        "flow": make_flow_from_dict({
            "Protocol": 6, "Flow Duration": 10,
            "Total Fwd Packets": 1, "Total Backward Packets": 1,
            "Fwd Packets Length Total": 0, "Bwd Packets Length Total": 0,
            "Fwd Packet Length Max": 0, "Bwd Packet Length Min": 0,
            "Fwd Header Length": 20, "Bwd Header Length": 20,
            "RST Flag Count": 1,
            "Fwd Packets/s": 100000.0, "Bwd Packets/s": 100000.0,
            "Init Fwd Win Bytes": 1024, "Init Bwd Win Bytes": 0,
            "Fwd Seg Size Min": 20,
        }),
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HÀM IN ĐẸP
# ─────────────────────────────────────────────────────────────────────────────

LABEL_ICON = {
    "Benign":   "✅",
    "DoS":      "🔴",
    "DDoS":     "🔴",
    "PortScan": "🟡",
    "ERROR":    "❌",
}

CONF_ICON = {
    "HIGH":    "🔵 Rất tự tin",
    "MEDIUM":  "🟡 Không chắc",
    "UNKNOWN": "❓ Không xác định",
}


def run_tests():
    print("=" * 72)
    print("   KIỂM THỬ SUY LUẬN AI — NIDS (DoS / DDoS / PortScan / Benign)")
    print("=" * 72)

    detector = AIDetector()
    status = detector.get_status()

    print("\n[1] Trạng thái hệ thống AI:")
    print(f"    - Mô hình NIDS Multiclass : {'✅ SẴN SÀNG' if status['models']['nids_multiclass'] else '❌ Chưa nạp'}")
    print(f"    - Label Encoder           : {'✅ SẴN SÀNG' if status['models']['label_encoder'] else '❌ Chưa nạp'}")
    print(f"    - Các lớp nhận diện       : {status['nids_classes']}")
    print(f"    - Ngưỡng độ tự tin cao    : >= {status['confidence_threshold'] * 100:.0f}%")
    if status['error']:
        print(f"    - Lỗi: {status['error']}")

    if not status['loaded']:
        print("\n❌ Không thể tiến hành kiểm thử vì mô hình chưa được nạp.")
        print("   Hãy chạy notebook Kaggle để lấy file model và đặt vào backend/models/ai/")
        return

    # ── Chạy từng test case ─────────────────────────────────────────────────
    print(f"\n[2] Chạy {len(TEST_CASES)} test case:\n")
    print(f"  {'#':>2}  {'Tên mẫu kiểm thử':<42} {'Kỳ vọng':>9} {'Dự đoán':>9} {'Tự tin':>8} {'Risk':>5} {'Đúng?':>6}")
    print("  " + "-" * 90)

    passed = 0
    low_conf_cases = []

    for idx, case in enumerate(TEST_CASES, start=1):
        result = detector.predict_flow(case["flow"])

        pred  = result["attack_type"]
        conf  = result["confidence"] * 100
        risk  = result["risk_score"]
        clvl  = result["confidence_level"]
        icon  = LABEL_ICON.get(pred, "❓")
        correct = "✅" if pred == case["expected"] else "❌"
        if pred == case["expected"]:
            passed += 1

        print(f"  {idx:>2}  {case['name']:<42} {case['expected']:>9} "
              f"{icon}{pred:>8} {conf:>7.1f}% {risk:>5} {correct:>5}")

        if result["confidence_level"] == "MEDIUM":
            low_conf_cases.append((idx, case["name"], pred, conf))

    # ── Tổng kết ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print(f"  KẾT QUẢ: {passed}/{len(TEST_CASES)} test case ĐÚNG "
          f"({'%.1f' % (passed/len(TEST_CASES)*100)}%)")
    print("=" * 72)

    if low_conf_cases:
        print(f"\n⚠️  {len(low_conf_cases)} dự đoán có độ tự tin DƯỚI 85% (cần theo dõi):")
        for idx, name, pred, conf in low_conf_cases:
            print(f"   Test #{idx}: \"{name}\" → {pred} ({conf:.1f}%)")

    # ── Bảng phân phối xác suất của test case cuối ───────────────────────────
    print("\n[3] Ví dụ phân phối xác suất (test case cuối cùng):")
    last_result = detector.predict_flow(TEST_CASES[-1]["flow"])
    for cls, prob in sorted(last_result["probabilities"].items(),
                            key=lambda x: x[1], reverse=True):
        bar = "█" * int(prob * 40)
        print(f"   {cls:12s} | {bar:<40} {prob*100:5.1f}%")

    print("\n✅ Hoàn tất kiểm thử!")


if __name__ == "__main__":
    run_tests()
