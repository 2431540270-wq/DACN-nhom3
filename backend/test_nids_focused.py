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

def make_flow(protocol=6, duration=50000, fwd_pkts=5, bwd_pkts=4,
              fwd_len=1500, bwd_len=1200, pkt_rate=10.0,
              syn=0, rst=0, ack=1, fin=0) -> list:
    """Tạo vector 77 đặc trưng với các giá trị chính, còn lại mặc định 0."""
    v = [0.0] * 77
    v[0]  = float(protocol)   # Protocol
    v[1]  = float(duration)   # Flow Duration
    v[2]  = float(fwd_pkts)   # Total Fwd Packets
    v[3]  = float(bwd_pkts)   # Total Backward Packets
    v[4]  = float(fwd_len)    # Fwd Packets Length Total
    v[5]  = float(bwd_len)    # Bwd Packets Length Total
    v[15] = float(pkt_rate)   # Flow Packets/s
    v[43] = float(syn)        # SYN Flag Count
    v[44] = float(rst)        # RST Flag Count
    v[45] = float(ack)        # ACK Flag Count (index 45 = PSH, 46 = ACK tùy dataset)
    v[42] = float(fin)        # FIN Flag Count
    return v


# Định nghĩa các mẫu kiểm thử và nhãn kỳ vọng
TEST_CASES = [
    {
        "name": "Lưu lượng HTTPS bình thường (Benign)",
        "expected": "Benign",
        "flow": make_flow(
            protocol=6, duration=120000, fwd_pkts=10, bwd_pkts=8,
            fwd_len=5000, bwd_len=4200, pkt_rate=15.0, ack=1
        ),
    },
    {
        "name": "HTTP GET thông thường (Benign)",
        "expected": "Benign",
        "flow": make_flow(
            protocol=6, duration=80000, fwd_pkts=4, bwd_pkts=3,
            fwd_len=400, bwd_len=6000, pkt_rate=8.0, ack=1
        ),
    },
    {
        "name": "SYN Flood — DDoS điển hình",
        "expected": "DDoS",
        "flow": make_flow(
            protocol=6, duration=50, fwd_pkts=8000, bwd_pkts=0,
            fwd_len=320000, bwd_len=0, pkt_rate=160000.0, syn=8000
        ),
    },
    {
        "name": "HTTP Flood — DDoS tầng ứng dụng",
        "expected": "DDoS",
        "flow": make_flow(
            protocol=6, duration=100, fwd_pkts=5000, bwd_pkts=2,
            fwd_len=200000, bwd_len=100, pkt_rate=50000.0, syn=5000
        ),
    },
    {
        "name": "DoS Hulk — tấn công lớn từ một nguồn",
        "expected": "DoS",
        "flow": make_flow(
            protocol=6, duration=200, fwd_pkts=3000, bwd_pkts=1,
            fwd_len=90000, bwd_len=50, pkt_rate=15000.0, syn=3000, rst=10
        ),
    },
    {
        "name": "Slowloris — DoS chậm giữ kết nối",
        "expected": "DoS",
        "flow": make_flow(
            protocol=6, duration=300000, fwd_pkts=50, bwd_pkts=2,
            fwd_len=500, bwd_len=20, pkt_rate=0.17, fin=0
        ),
    },
    {
        "name": "Dò quét nhanh nhiều cổng (PortScan — SYN scan)",
        "expected": "PortScan",
        "flow": make_flow(
            protocol=6, duration=20, fwd_pkts=1, bwd_pkts=0,
            fwd_len=44, bwd_len=0, pkt_rate=50.0, syn=1, rst=1
        ),
    },
    {
        "name": "Dò quét UDP (PortScan)",
        "expected": "PortScan",
        "flow": make_flow(
            protocol=17, duration=10, fwd_pkts=1, bwd_pkts=0,
            fwd_len=28, bwd_len=0, pkt_rate=100.0, syn=0
        ),
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
