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
    AIDetector — Động cơ AI phát hiện xâm nhập mạng (NIDS)
    Được huấn luyện trên Kaggle với dữ liệu CICIDS2017/2018
    sử dụng kỹ thuật 4-Fold Stratified Cross Validation với XGBoost (GPU).

    Tập trung vào 4 nhóm mối đe dọa mạng chính:
        - Benign    : Lưu lượng mạng bình thường, an toàn.
        - DoS       : Tấn công từ chối dịch vụ (Hulk, GoldenEye, Slowloris...).
        - DDoS      : Tấn công từ chối dịch vụ phân tán (LOIC, HOIC, DNS Flood...).
        - PortScan  : Dò quét cổng dịch vụ (nmap, masscan...).

    Bao gồm 1 mô hình:
        XGBoost Multiclass (model_nids_multiclass.json):
            Phân loại trực tiếp thành 4 nhóm với xác suất từng lớp (soft-prob).
            Ngưỡng độ tự tin: >= 0.85 → "Rất tự tin", < 0.85 → "Nghi vấn".
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

        # NIDS Multiclass model (XGBoost) — nhận diện 4 lớp tấn công mạng
        self.model_multiclass: Optional[xgb.Booster] = None

        # Label encoder — ánh xạ số nguyên sang tên nhãn (Benign, DoS, DDoS, PortScan)
        self.label_encoder = None

        # Danh sách nhãn sau khi nạp encoder
        self.nids_classes: List[str] = []

        self.is_loaded = False
        self.load_error = None

        self._load_models()
        self._initialized = True

    # ─────────────────────────────────────────────────────────────────────────
    # NẠP MÔ HÌNH
    # ─────────────────────────────────────────────────────────────────────────
    def _load_models(self):
        """Nạp các mô hình NIDS đã huấn luyện từ thư mục backend/models/ai"""
        try:
            print(f"[AIDetector] Đang nạp mô hình từ: {self.model_dir}")

            if not XGB_AVAILABLE:
                raise ImportError("Thư viện xgboost chưa được cài đặt! Chạy: pip install xgboost")

            # 1. Nạp Label Encoder (Benign / DoS / DDoS / PortScan)
            le_path = os.path.join(self.model_dir, "label_encoder_multiclass.pkl")
            if os.path.exists(le_path):
                with open(le_path, "rb") as f:
                    self.label_encoder = pickle.load(f)
                if hasattr(self.label_encoder, "classes_"):
                    self.nids_classes = [str(c) for c in self.label_encoder.classes_]
                print(f"[AIDetector] ✅ Nạp label_encoder_multiclass.pkl thành công! Nhãn: {self.nids_classes}")
            else:
                print(f"[AIDetector] ⚠️ Không tìm thấy file: {le_path}")

            # 2. Nạp XGBoost Multiclass (phân loại 4 lớp trực tiếp)
            multi_path = os.path.join(self.model_dir, "model_nids_multiclass.json")
            if os.path.exists(multi_path):
                self.model_multiclass = xgb.Booster()
                self.model_multiclass.load_model(multi_path)
                print("[AIDetector] ✅ Nạp model_nids_multiclass.json thành công!")
            else:
                print(f"[AIDetector] ⚠️ Không tìm thấy file: {multi_path}")

            self.is_loaded = self.model_multiclass is not None
            if self.is_loaded:
                print("[AIDetector] ✅ Hệ thống NIDS sẵn sàng. Các lớp nhận diện:", self.nids_classes)
            else:
                print("[AIDetector] ⚠️ Không có mô hình nào được nạp thành công.")

        except Exception as e:
            self.load_error = str(e)
            print(f"[AIDetector] ❌ Lỗi khi nạp mô hình: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # DỰ ĐOÁN LUỒNG MẠNG NIDS
    # ─────────────────────────────────────────────────────────────────────────
    def predict_flow(self, features: Union[List[float], np.ndarray, Dict[str, float]]) -> Dict[str, Any]:
        """
        Dự đoán loại lưu lượng mạng dựa trên 77 đặc trưng CICFlowMeter.

        Args:
            features: Danh sách / ndarray / dict gồm 77 đặc trưng số của luồng mạng.

        Returns:
            dict với các khóa:
                - is_attack       (bool)  : True nếu phát hiện tấn công.
                - attack_type     (str)   : Nhãn dự đoán (Benign / DoS / DDoS / PortScan).
                - confidence      (float) : Xác suất lớp được dự đoán (0.0 – 1.0).
                - confidence_level(str)   : "HIGH" (>= 0.85) hoặc "MEDIUM" (< 0.85).
                - risk_score      (int)   : Điểm rủi ro 0 – 100.
                - probabilities   (dict)  : Phân phối xác suất toàn bộ 4 lớp.
                - status          (str)   : "OK" hoặc thông báo lỗi.
        """
        if not XGB_AVAILABLE or self.model_multiclass is None:
            return {
                "is_attack": False,
                "attack_type": "Benign",
                "confidence": 0.0,
                "confidence_level": "UNKNOWN",
                "risk_score": 0,
                "probabilities": {},
                "status": "MODEL_NOT_READY"
            }

        try:
            # Chuẩn bị vector đặc trưng
            if isinstance(features, dict):
                feat_values = list(features.values())
            else:
                feat_values = list(features)

            arr = np.array([feat_values], dtype=np.float32)
            # Thay thế giá trị vô cực hoặc NaN bằng 0 / giá trị an toàn
            arr = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)

            dmat = xgb.DMatrix(arr)

            # Dự đoán xác suất 4 lớp (multi:softprob)
            raw_probs = self.model_multiclass.predict(dmat)  # shape (1, 4)
            probs = raw_probs[0]                             # shape (4,)

            pred_idx = int(np.argmax(probs))
            confidence = float(probs[pred_idx])

            # Ánh xạ index → tên nhãn
            if self.label_encoder and hasattr(self.label_encoder, "classes_"):
                attack_type = str(self.label_encoder.classes_[pred_idx])
            elif self.nids_classes and pred_idx < len(self.nids_classes):
                attack_type = self.nids_classes[pred_idx]
            else:
                attack_type = f"Class_{pred_idx}"

            is_attack = (attack_type.lower() != "benign")

            # Phân phối xác suất theo tên nhãn
            prob_dict = {}
            if self.nids_classes:
                prob_dict = {
                    cls: round(float(p), 4)
                    for cls, p in zip(self.nids_classes, probs)
                }

            # Mức độ tự tin
            confidence_level = "HIGH" if confidence >= 0.85 else "MEDIUM"

            # Điểm rủi ro: Benign = 0, tấn công = tỷ lệ theo confidence
            risk_score = 0
            if is_attack:
                risk_score = min(100, max(50, int(confidence * 100)))

            return {
                "is_attack": is_attack,
                "attack_type": attack_type,
                "confidence": round(confidence, 4),
                "confidence_level": confidence_level,
                "risk_score": risk_score,
                "probabilities": prob_dict,
                "status": "OK"
            }

        except Exception as e:
            print(f"[AIDetector] ❌ Lỗi dự đoán luồng mạng: {e}")
            return {
                "is_attack": False,
                "attack_type": "ERROR",
                "confidence": 0.0,
                "confidence_level": "UNKNOWN",
                "risk_score": 0,
                "probabilities": {},
                "status": f"ERROR: {str(e)}"
            }

    # ─────────────────────────────────────────────────────────────────────────
    # TRẠNG THÁI HỆ THỐNG
    # ─────────────────────────────────────────────────────────────────────────
    def get_status(self) -> Dict[str, Any]:
        """Lấy thông tin trạng thái các model đang hoạt động"""
        return {
            "loaded": self.is_loaded,
            "model_dir": self.model_dir,
            "focus": "NIDS — DoS / DDoS / PortScan Detection",
            "models": {
                "nids_multiclass": self.model_multiclass is not None,
                "label_encoder": self.label_encoder is not None,
            },
            "nids_classes": self.nids_classes,
            "confidence_threshold": 0.85,
            "error": self.load_error
        }
