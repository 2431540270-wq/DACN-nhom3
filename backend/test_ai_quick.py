"""
test_ai_quick.py — Kiểm tra nhanh chức năng của AIDetector sau khi sửa lỗi
"""
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from core.ai_detector import AIDetector, FEATURE_COLS

def main():
    print("=== TEST AI DETECTOR ===")
    detector = AIDetector()
    print("Model status:", detector.get_status())

    # 1. Test predict_payload
    payloads = [
        ("SELECT * FROM users WHERE id = '1' OR '1'='1' --", "sqli"),
        ("<script>alert('XSS')</script>", "xss"),
        ("../../etc/passwd", "path_traversal"),
        ("; cat /etc/shadow && whoami", "cmdi"),
        ("hello world from regular user", "norm")
    ]

    print("\n--- Test Payload Detection ---")
    for text, expected in payloads:
        res = detector.predict_payload(text)
        print(f"Payload: {text[:35]:<35} -> Type: {res['attack_type']:<15} Risk: {res['risk_score']:<3} IsAttack: {res['is_attack']}")
        assert res["is_attack"] == (expected != "norm"), f"Expected attack={expected != 'norm'} for {text}"

    # 2. Test predict_flow với list
    print("\n--- Test Flow Detection (Vector) ---")
    vec = [0.0] * 77
    vec[0] = 6.0  # TCP
    vec[1] = 50000.0  # Flow Duration
    res_vec = detector.predict_flow(vec)
    print("Vector predict result:", res_vec["attack_type"], "Conf:", res_vec["confidence"])

    # 3. Test predict_flow với dict
    print("\n--- Test Flow Detection (Dict) ---")
    d = {col: 0.0 for col in FEATURE_COLS}
    d["Protocol"] = 6.0
    d["Flow Duration"] = 50000.0
    res_dict = detector.predict_flow(d)
    print("Dict predict result:  ", res_dict["attack_type"], "Conf:", res_dict["confidence"])

    print("\n✅ TẤT CẢ CÁC BÀI TEST ĐÃ VƯỢT QUA THÀNH CÔNG!")

if __name__ == "__main__":
    main()
