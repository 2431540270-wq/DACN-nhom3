import os
import sys
import re
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

try:
    # pyrefly: ignore[missing-import]
    import torch
    # pyrefly: ignore[missing-import]
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


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


# ─────────────────────────────────────────────────────────────────────────────
# Deep Neural Network Architecture (phải giống hệt file train)
# ─────────────────────────────────────────────────────────────────────────────
if TORCH_AVAILABLE:
    class ResidualBlock(nn.Module):
        """Residual Block với BatchNorm và GELU activation."""
        def __init__(self, dim, dropout=0.3):
            super().__init__()
            self.block = nn.Sequential(
                nn.Linear(dim, dim),
                nn.BatchNorm1d(dim),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(dim, dim),
                nn.BatchNorm1d(dim),
            )
            self.act = nn.GELU()
            self.dropout = nn.Dropout(dropout)

        def forward(self, x):
            return self.dropout(self.act(self.block(x) + x))

    class NIDSDeepNet(nn.Module):
        """
        Deep Neural Network cho Network Intrusion Detection.
        Kiến trúc: Input → 4 Residual Blocks → Feature Squeeze → Classification
        """
        def __init__(self, input_dim=77, num_classes=4, hidden_dim=512, n_blocks=4, dropout=0.3):
            super().__init__()
            self.input_proj = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.GELU(),
                nn.Dropout(dropout * 0.5),
            )
            self.res_blocks = nn.Sequential(
                *[ResidualBlock(hidden_dim, dropout) for _ in range(n_blocks)]
            )
            self.squeeze = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.BatchNorm1d(hidden_dim // 2),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim // 2, hidden_dim // 4),
                nn.BatchNorm1d(hidden_dim // 4),
                nn.GELU(),
                nn.Dropout(dropout * 0.5),
            )
            self.classifier = nn.Linear(hidden_dim // 4, num_classes)

        def forward(self, x):
            x = self.input_proj(x)
            x = self.res_blocks(x)
            x = self.squeeze(x)
            return self.classifier(x)


class AIDetector:
    """
    AIDetector — Động cơ AI phát hiện xâm nhập mạng (NIDS)
    Được huấn luyện trên Kaggle với dữ liệu CICIDS2017/2018
    sử dụng kiến trúc Hybrid Ensemble: XGBoost + Deep Neural Network (DNN).

    Tập trung vào 4 nhóm mối đe dọa mạng chính:
        - Benign    : Lưu lượng mạng bình thường, an toàn.
        - DoS       : Tấn công từ chối dịch vụ (Hulk, GoldenEye, Slowloris...).
        - DDoS      : Tấn công từ chối dịch vụ phân tán (LOIC, HOIC, DNS Flood...).
        - PortScan  : Dò quét cổng dịch vụ (nmap, masscan...).

    Bao gồm 2 mô hình kết hợp Ensemble:
        XGBoost Multiclass (model_nids_multiclass.json):
            Gradient Boosted Trees — mạnh với tabular data.
        Deep Neural Network (model_nids_dnn.pt):
            Mạng Fully-Connected sâu với Residual Blocks, BatchNorm, GELU.
        Ensemble:
            Trung bình xác suất có trọng số từ cả 2 model.
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

        # NIDS Deep Neural Network (PyTorch)
        self.model_dnn = None
        self.dnn_device = None

        # StandardScaler cho DNN (cần scale input trước khi đưa vào DNN)
        self.scaler = None

        # Trọng số Ensemble
        self.ensemble_w_xgb = 0.55
        self.ensemble_w_dnn = 0.45

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

            # 3. Nạp StandardScaler (cho DNN)
            scaler_path = os.path.join(self.model_dir, "standard_scaler.pkl")
            if os.path.exists(scaler_path):
                with open(scaler_path, "rb") as f:
                    self.scaler = pickle.load(f)
                print("[AIDetector] ✅ Nạp standard_scaler.pkl thành công!")
            else:
                print(f"[AIDetector] ⚠️ Không tìm thấy file: {scaler_path}")

            # 4. Nạp DNN model (PyTorch)
            dnn_path = os.path.join(self.model_dir, "model_nids_dnn.pt")
            if os.path.exists(dnn_path) and TORCH_AVAILABLE:
                # Chọn device: GPU nếu có, không thì CPU
                self.dnn_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

                checkpoint = torch.load(dnn_path, map_location=self.dnn_device, weights_only=False)
                arch = checkpoint.get('architecture', {})

                self.model_dnn = NIDSDeepNet(
                    input_dim=arch.get('input_dim', 77),
                    num_classes=arch.get('num_classes', 4),
                    hidden_dim=arch.get('hidden_dim', 512),
                    n_blocks=arch.get('n_blocks', 4),
                    dropout=arch.get('dropout', 0.3),
                )
                self.model_dnn.load_state_dict(checkpoint['model_state_dict'])
                self.model_dnn.to(self.dnn_device)
                self.model_dnn.eval()

                # Đọc trọng số ensemble từ checkpoint
                ew = checkpoint.get('ensemble_weights', {})
                self.ensemble_w_xgb = ew.get('xgboost', 0.55)
                self.ensemble_w_dnn = ew.get('dnn', 0.45)

                print(f"[AIDetector] ✅ Nạp model_nids_dnn.pt thành công! Device: {self.dnn_device}")
                print(f"[AIDetector]    Ensemble weights: XGB={self.ensemble_w_xgb}, DNN={self.ensemble_w_dnn}")
            elif not TORCH_AVAILABLE:
                print("[AIDetector] ⚠️ PyTorch chưa được cài. DNN sẽ không khả dụng, chỉ dùng XGBoost.")
            else:
                print(f"[AIDetector] ⚠️ Không tìm thấy file: {dnn_path}")

            self.is_loaded = self.model_multiclass is not None
            if self.is_loaded:
                mode = "Hybrid Ensemble (XGB+DNN)" if self.model_dnn else "XGBoost Only"
                print(f"[AIDetector] ✅ Hệ thống NIDS sẵn sàng [{mode}]. "
                      f"Các lớp nhận diện: {self.nids_classes}")
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
        Sử dụng Hybrid Ensemble: XGBoost + DNN nếu cả 2 model có sẵn,
        hoặc fallback về XGBoost-only nếu DNN không khả dụng.

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
                - model_used      (str)   : "ensemble" hoặc "xgboost_only".
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
                "model_used": "none",
                "status": "MODEL_NOT_READY"
            }

        try:
            # Chuẩn bị vector đặc trưng
            if isinstance(features, dict):
                # Nếu dict có các key trùng với FEATURE_COLS thì map đúng thứ tự 77 đặc trưng
                if any(k in features for k in FEATURE_COLS):
                    feat_values = [float(features.get(col, 0.0)) for col in FEATURE_COLS]
                else:
                    feat_values = list(features.values())
            else:
                feat_values = list(features)

            arr = np.array([feat_values], dtype=np.float32)
            # Thay thế giá trị vô cực hoặc NaN bằng 0 / giá trị an toàn
            arr = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)

            # ── XGBoost prediction ───────────────────────────────────────
            dmat = xgb.DMatrix(arr)
            xgb_probs = self.model_multiclass.predict(dmat)[0]  # shape (4,)

            # ── DNN prediction (nếu có) ──────────────────────────────────
            model_used = "xgboost_only"
            final_probs = xgb_probs

            if self.model_dnn is not None and self.scaler is not None and TORCH_AVAILABLE:
                try:
                    # Scale input cho DNN
                    arr_scaled = self.scaler.transform(arr).astype(np.float32)
                    x_tensor = torch.FloatTensor(arr_scaled).to(self.dnn_device)

                    self.model_dnn.eval()
                    with torch.no_grad():
                        dnn_logits = self.model_dnn(x_tensor)
                        dnn_probs = torch.softmax(dnn_logits, dim=-1).cpu().numpy()[0]

                    # Ensemble: trung bình có trọng số
                    final_probs = (self.ensemble_w_xgb * xgb_probs +
                                   self.ensemble_w_dnn * dnn_probs)
                    model_used = "ensemble"
                except Exception as e:
                    # Fallback về XGBoost nếu DNN lỗi
                    print(f"[AIDetector] ⚠️ DNN inference lỗi, fallback XGBoost: {e}")
                    final_probs = xgb_probs
                    model_used = "xgboost_only"

            pred_idx = int(np.argmax(final_probs))
            confidence = float(final_probs[pred_idx])

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
                    for cls, p in zip(self.nids_classes, final_probs)
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
                "model_used": model_used,
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
                "model_used": "error",
                "status": f"ERROR: {str(e)}"
            }

    # ─────────────────────────────────────────────────────────────────────────
    # DỰ ĐOÁN PAYLOAD WEB (SQLi / XSS / Path Traversal / Command Injection)
    # ─────────────────────────────────────────────────────────────────────────
    def predict_payload(self, text: str) -> Dict[str, Any]:
        """
        Phân tích chuỗi payload HTTP / Web bằng rule-based regex detection.
        Hỗ trợ nhận diện các mẫu SQLi, XSS, Path Traversal, Command Injection.
        """
        if not text or not isinstance(text, str):
            return {
                "is_attack": False,
                "attack_type": "norm",
                "risk_score": 0,
                "confidence": 0.95,
                "details": "Empty payload"
            }

        patterns = {
            "sqli": [
                r"(\b(UNION(\s+ALL)?|SELECT|DROP|INSERT|DELETE|UPDATE)\b)",
                r"('.*--)",
                r"('(\s*)[oO][rR](\s*)'\d+'\s*=\s*'\d+)",
                r"('(\s*)[oO][rR](\s*)\d+\s*=\s*\d+)",
                r"(\b(ORDER|GROUP)\s+BY\b)",
                r"(\bHAVING\b)",
                r"(\b(SLEEP|BENCHMARK)\s*\()",
            ],
            "xss": [
                r"(<script[^>]*>.*?</script>)",
                r"(javascript\s*:)",
                r"(on(load|error|click|mouseover|submit)\s*=)",
                r"(alert\s*\(.*?\))",
                r"(<img[^>]+src=[^>]*>)",
                r"(<svg[^>]*>)",
                r"(eval\s*\(.*?\))",
            ],
            "path_traversal": [
                r"(\.\./|\.\.\\)",
                r"(/etc/(passwd|shadow|hosts))",
                r"(c:\\windows\\system32)",
                r"(cmd\.exe|boot\.ini)",
            ],
            "cmdi": [
                r"(;\s*(ls|dir|cat|whoami|id|uname|pwd)\b)",
                r"(\|\s*(ls|dir|cat|whoami|id|uname)\b)",
                r"(&&\s*(ls|dir|cat|whoami|id|uname)\b)",
                r"(\$\(.*?\))",
                r"(`.*?`)",
                r"(\bexec\s*\()",
            ]
        }

        matched_types = {}
        for attack_name, pat_list in patterns.items():
            matches = []
            for pat in pat_list:
                if re.search(pat, text, re.IGNORECASE):
                    matches.append(pat)
            if matches:
                matched_types[attack_name] = len(matches)

        if not matched_types:
            return {
                "is_attack": False,
                "attack_type": "norm",
                "risk_score": 5,
                "confidence": 0.90,
                "details": "No attack pattern detected"
            }

        primary_attack = max(matched_types.items(), key=lambda x: x[1])
        attack_type = primary_attack[0]
        match_count = sum(matched_types.values())

        if match_count >= 3:
            risk_score = 85
            confidence = 0.95
        elif match_count == 2:
            risk_score = 65
            confidence = 0.80
        else:
            risk_score = 45
            confidence = 0.65

        return {
            "is_attack": True,
            "attack_type": attack_type,
            "risk_score": risk_score,
            "confidence": confidence,
            "details": f"Matched {match_count} pattern(s) for {attack_type}"
        }

    # ─────────────────────────────────────────────────────────────────────────
    # TRẠNG THÁI HỆ THỐNG
    # ─────────────────────────────────────────────────────────────────────────
    def get_status(self) -> Dict[str, Any]:
        """Lấy thông tin trạng thái các model đang hoạt động"""
        mode = "Hybrid Ensemble (XGBoost + DNN)"
        if self.model_dnn is None:
            mode = "XGBoost Only"
        if self.model_multiclass is None:
            mode = "Not Loaded"

        return {
            "loaded": self.is_loaded,
            "model_dir": self.model_dir,
            "focus": "NIDS — DoS / DDoS / PortScan Detection",
            "inference_mode": mode,
            "models": {
                "nids_xgboost": self.model_multiclass is not None,
                "nids_dnn": self.model_dnn is not None,
                "standard_scaler": self.scaler is not None,
                "label_encoder": self.label_encoder is not None,
            },
            "ensemble_weights": {
                "xgboost": self.ensemble_w_xgb,
                "dnn": self.ensemble_w_dnn,
            },
            "nids_classes": self.nids_classes,
            "confidence_threshold": 0.85,
            "dnn_device": str(self.dnn_device) if self.dnn_device else None,
            "error": self.load_error
        }
