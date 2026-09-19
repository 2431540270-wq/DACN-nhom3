import os
import sys
import pickle
import warnings
from typing import Dict, Any, List, Optional, Union
# pyrefly: ignore [missing-import]
import numpy as np

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Bỏ qua các cảnh báo version scikit-learn giữa môi trường huấn luyện và local
warnings.filterwarnings("ignore")

try:
    # pyrefly: ignore [missing-import]
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False


class AIDetector:
    """
    AIDetector — Động cơ AI phát hiện xâm nhập (NIDS) và tấn công Web (WAF)
    Được huấn luyện trên Kaggle với dữ liệu CICIDS2017/2018 và CSIC-2010 Web Payload.
    
    Bao gồm 3 mô hình:
      1. XGBoost Binary: Phân loại nhị phân Benign vs Attack (Độ chính xác: 99.82%)
      2. XGBoost Multiclass: Phân loại 9 nhóm tấn công mạng (Benign, DDoS, DoS, BruteForce,...)
      3. TF-IDF + LogReg Pipeline: Phân loại 5 nhóm payload web (norm, sqli, xss, cmdi, path-traversal)
    """

    _instance = None  # Singleton pattern để chỉ nạp model một lần duy nhất

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(AIDetector, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, model_dir: Optional[str] = None):
        if self._initialized:
            return

        if model_dir is None:
            # Mặc định trỏ đến backend/models/ai
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            model_dir = os.path.join(base_dir, "models", "ai")

        self.model_dir = model_dir
        self.model_binary = None
        self.model_multiclass = None
        self.label_encoder = None
        self.model_web = None

        self.nids_classes = []
        self.web_classes = []
        self.is_loaded = False
        self.load_error = None

        self._load_models()
        self._initialized = True

    def _load_models(self):
        """Nạp các mô hình đã huấn luyện từ thư mục backend/models/ai"""
        try:
            print(f"[AIDetector] Đang nạp mô hình từ: {self.model_dir}")

            # 1. Nạp Web Payload Model (TF-IDF + Logistic Regression)
            web_path = os.path.join(self.model_dir, "model_web_payload.pkl")
            if os.path.exists(web_path):
                with open(web_path, "rb") as f:
                    self.model_web = pickle.load(f)
                if hasattr(self.model_web, "classes_"):
                    self.web_classes = [str(c) for c in self.model_web.classes_]
                print(f"[AIDetector]  Nạp model_web_payload.pkl thành công! Nhãn: {self.web_classes}")
            else:
                print(f"[AIDetector] ⚠️ Không tìm thấy file: {web_path}")

            # 2. Nạp Label Encoder Multiclass
            le_path = os.path.join(self.model_dir, "label_encoder_multiclass.pkl")
            if os.path.exists(le_path):
                with open(le_path, "rb") as f:
                    self.label_encoder = pickle.load(f)
                if hasattr(self.label_encoder, "classes_"):
                    self.nids_classes = [str(c) for c in self.label_encoder.classes_]
                print(f"[AIDetector]  Nạp label_encoder_multiclass.pkl thành công! Nhãn: {self.nids_classes}")
            else:
                print(f"[AIDetector] ⚠️ Không tìm thấy file: {le_path}")

            # 3. Nạp XGBoost Models
            if XGB_AVAILABLE:
                # NIDS Binary
                bin_path = os.path.join(self.model_dir, "model_nids_binary.json")
                if os.path.exists(bin_path):
                    self.model_binary = xgb.Booster()
                    self.model_binary.load_model(bin_path)
                    print("[AIDetector]  Nạp model_nids_binary.json thành công!")
                else:
                    print(f"[AIDetector] ⚠️ Không tìm thấy file: {bin_path}")

                # NIDS Multiclass
                multi_path = os.path.join(self.model_dir, "model_nids_multiclass.json")
                if os.path.exists(multi_path):
                    self.model_multiclass = xgb.Booster()
                    self.model_multiclass.load_model(multi_path)
                    print("[AIDetector]  Nạp model_nids_multiclass.json thành công!")
                else:
                    print(f"[AIDetector] ⚠️ Không tìm thấy file: {multi_path}")
            else:
                print("[AIDetector] ⚠️ Thư viện xgboost chưa được cài đặt!")

            self.is_loaded = (self.model_web is not None) or (self.model_binary is not None)
            print("[AIDetector]  Khởi tạo hoàn tất. Hệ thống sẵn sàng nhận diện AI.")

        except Exception as e:
            self.load_error = str(e)
            print(f"[AIDetector]  Lỗi khi nạp mô hình: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # 1. DỰ ĐOÁN WEB PAYLOAD (SQLi, XSS, CMDi, Path Traversal, Normal)
    # ─────────────────────────────────────────────────────────────────────────
    def predict_payload(self, payload: str) -> Dict[str, Any]:
        """
        Dự đoán tấn công ứng dụng web từ chuỗi payload (URL, Query, Body, Header).
        Trả về phân loại chi tiết và độ tin cậy.
        """
        if not payload or not isinstance(payload, str) or not payload.strip():
            return {
                "payload": payload or "",
                "is_attack": False,
                "attack_type": "norm",
                "confidence": 1.0,
                "risk_score": 0,
                "probabilities": {"norm": 1.0}
            }

        if self.model_web is None:
            # Fallback nếu model chưa sẵn sàng: kiểm tra regex cơ bản
            return self._fallback_payload_check(payload)

        try:
            # Dự đoán xác suất qua Pipeline TF-IDF + LogisticRegression
            probs = self.model_web.predict_proba([payload])[0]
            pred_idx = int(np.argmax(probs))
            predicted_class = str(self.web_classes[pred_idx]) if self.web_classes else "norm"
            confidence = float(probs[pred_idx])

            prob_dict = {
                cls_name: round(float(prob), 4)
                for cls_name, prob in zip(self.web_classes, probs)
            }

            is_attack = (predicted_class.lower() != "norm")

            # Tính điểm rủi ro từ 0-100 dựa trên độ tự tin
            risk_score = 0
            if is_attack:
                risk_score = min(100, int(confidence * 100))

            return {
                "payload": payload,
                "is_attack": is_attack,
                "attack_type": predicted_class,
                "confidence": round(confidence, 4),
                "risk_score": risk_score,
                "probabilities": prob_dict
            }
        except Exception as e:
            print(f"[AIDetector] Lỗi khi dự đoán payload: {e}")
            return self._fallback_payload_check(payload)

    def _fallback_payload_check(self, payload: str) -> Dict[str, Any]:
        """Quy tắc dự phòng nếu model chưa nạp"""
        p_lower = payload.lower()
        if any(kw in p_lower for kw in ["union select", "' or 1=1", "--", "select *", "sleep("]):
            return {"payload": payload, "is_attack": True, "attack_type": "sqli", "confidence": 0.85, "risk_score": 85, "probabilities": {"sqli": 0.85}}
        if any(kw in p_lower for kw in ["<script", "javascript:", "onerror=", "onload="]):
            return {"payload": payload, "is_attack": True, "attack_type": "xss", "confidence": 0.85, "risk_score": 85, "probabilities": {"xss": 0.85}}
        if any(kw in p_lower for kw in ["../", "..\\", "/etc/passwd", "win.ini"]):
            return {"payload": payload, "is_attack": True, "attack_type": "path-traversal", "confidence": 0.85, "risk_score": 85, "probabilities": {"path-traversal": 0.85}}
        if any(kw in p_lower for kw in ["; cat ", "| whoami", "&& dir", "bash -i"]):
            return {"payload": payload, "is_attack": True, "attack_type": "cmdi", "confidence": 0.85, "risk_score": 85, "probabilities": {"cmdi": 0.85}}
        return {"payload": payload, "is_attack": False, "attack_type": "norm", "confidence": 0.95, "risk_score": 0, "probabilities": {"norm": 0.95}}

    # ─────────────────────────────────────────────────────────────────────────
    # 2. DỰ ĐOÁN LUỒNG MẠNG NIDS (Benign, DDoS, DoS, BruteForce, PortScan,...)
    # ─────────────────────────────────────────────────────────────────────────
    def predict_flow(self, features: Union[List[float], np.ndarray, Dict[str, float]]) -> Dict[str, Any]:
        """
        Dự đoán luồng mạng dựa trên 77 đặc trưng CICFlowMeter.
        Chạy mô hình nhị phân (Binary) trước, nếu là tấn công thì phân loại chi tiết (Multiclass).
        """
        if not XGB_AVAILABLE or self.model_binary is None:
            return {
                "is_attack": False,
                "attack_type": "Benign",
                "confidence": 0.0,
                "risk_score": 0,
                "status": "MODEL_NOT_READY"
            }

        try:
            # Chuẩn bị dữ liệu đầu vào cho XGBoost DMatrix
            if isinstance(features, dict):
                # Nếu đưa vào dạng dictionary đặc trưng
                feat_values = list(features.values())
            else:
                feat_values = list(features)

            arr = np.array([feat_values], dtype=np.float32)
            # Thay thế giá trị vô cực hoặc NaN
            arr = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)

            dmat = xgb.DMatrix(arr)

            # 1. Dự đoán Binary (0: Benign, 1: Attack)
            bin_raw = self.model_binary.predict(dmat)
            bin_prob = float(bin_raw[0])
            is_attack = (bin_prob >= 0.5)

            attack_type = "Benign"
            confidence = 1.0 - bin_prob if not is_attack else bin_prob
            multi_probs = {}

            # 2. Nếu là Attack và có model Multiclass, phân loại nhóm cụ thể
            if is_attack and self.model_multiclass is not None:
                multi_raw = self.model_multiclass.predict(dmat)
                probs = multi_raw[0]
                pred_idx = int(np.argmax(probs))

                if self.label_encoder and hasattr(self.label_encoder, "classes_"):
                    attack_type = str(self.label_encoder.classes_[pred_idx])
                elif self.nids_classes and pred_idx < len(self.nids_classes):
                    attack_type = self.nids_classes[pred_idx]
                else:
                    attack_type = f"Attack_Class_{pred_idx}"

                confidence = float(probs[pred_idx])

                if self.nids_classes:
                    multi_probs = {
                        cls_name: round(float(p), 4)
                        for cls_name, p in zip(self.nids_classes, probs)
                    }
            elif not is_attack:
                attack_type = "Benign"

            risk_score = 0
            if is_attack:
                risk_score = min(100, max(50, int(confidence * 100)))

            return {
                "is_attack": is_attack,
                "attack_type": attack_type,
                "confidence": round(confidence, 4),
                "risk_score": risk_score,
                "probabilities": multi_probs
            }

        except Exception as e:
            print(f"[AIDetector] Lỗi dự đoán luồng mạng: {e}")
            return {
                "is_attack": False,
                "attack_type": "ERROR",
                "error": str(e),
                "risk_score": 0
            }

    # ─────────────────────────────────────────────────────────────────────────
    # 3. TRẠNG THÁI HỆ THỐNG
    # ─────────────────────────────────────────────────────────────────────────
    def get_status(self) -> Dict[str, Any]:
        """Lấy thông tin trạng thái các model đang hoạt động"""
        return {
            "loaded": self.is_loaded,
            "model_dir": self.model_dir,
            "models": {
                "nids_binary": self.model_binary is not None,
                "nids_multiclass": self.model_multiclass is not None,
                "web_payload": self.model_web is not None,
                "label_encoder": self.label_encoder is not None
            },
            "nids_classes": self.nids_classes,
            "web_classes": self.web_classes,
            "error": self.load_error
        }
