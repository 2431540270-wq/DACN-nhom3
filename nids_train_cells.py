"""
=============================================================================
HƯỚNG DẪN SỬ DỤNG FILE NÀY TRÊN KAGGLE
=============================================================================
1. Vào Kaggle → "New Notebook" → chọn "Python".
2. Vào Settings → chọn Accelerator = "GPU T4 x2".
3. Thêm 2 Dataset vào Notebook (Add Data → Search):
   - "CICIDS2017"  (ví dụ: chethuhn/network-intrusion-dataset)
   - "CSE-CIC-IDS2018" (ví dụ: solarmainframe/ids-intrusion-csv)
   Chúng sẽ tự động mount vào /kaggle/input/
4. Copy từng ô code bên dưới (từ # %% đến # %% tiếp theo) vào từng Cell.
5. Chạy tuần tự từ trên xuống dưới.
=============================================================================

FILE NÀY ĐƯỢC CHIA THÀNH 13 CELL, MỖI CELL CÁCH NHAU BẰNG DẤU  # %%
Ký hiệu  # %%  = bắt đầu một cell mới trong Kaggle Notebook.

KIẾN TRÚC: Hybrid Ensemble = XGBoost + Deep Neural Network (DNN)
  - XGBoost: Gradient Boosted Trees (tối ưu GPU)
  - DNN: Mạng Fully-Connected sâu với BatchNorm, Dropout, Residual, GELU
  - Ensemble: Trung bình xác suất có trọng số từ cả 2 model
=============================================================================
"""

# %%
# ============================================================================
# CELL 1 — Cài đặt thêm thư viện (chạy 1 lần)
# ============================================================================
import subprocess, sys

def pip_install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])

pip_install("xgboost")
pip_install("scikit-learn")
pip_install("matplotlib")
pip_install("seaborn")
# PyTorch thường đã có sẵn trên Kaggle GPU, nhưng đảm bảo an toàn
try:
    # pyrefly: ignore[missing-import]
    import torch
    print(f"✅ PyTorch đã sẵn sàng: {torch.__version__}")
except ImportError:
    pip_install("torch")
    # pyrefly: ignore[missing-import]
    import torch
    print(f"✅ Đã cài PyTorch: {torch.__version__}")

print("✅ Đã cài đặt xong thư viện.")


# %%
# ============================================================================
# CELL 2 — Import thư viện & cấu hình toàn cục
# ============================================================================
import os, json, pickle, warnings, glob
# pyrefly: ignore [missing-import]
import numpy as np
import pandas as pd
# pyrefly: ignore [missing-import]
import matplotlib.pyplot as plt
import seaborn as sns

# pyrefly: ignore [missing-import]
import xgboost as xgb
# pyrefly: ignore[missing-import]
import torch
# pyrefly: ignore[missing-import]
import torch.nn as nn
# pyrefly: ignore[missing-import]
import torch.optim as optim
# pyrefly: ignore[missing-import]
from torch.utils.data import DataLoader, TensorDataset

from sklearn.preprocessing import LabelEncoder, StandardScaler, label_binarize
# pyrefly: ignore[missing-import]
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    accuracy_score, f1_score, log_loss,
    confusion_matrix, classification_report, brier_score_loss
)
from sklearn.utils.class_weight import compute_sample_weight, compute_class_weight

warnings.filterwarnings("ignore")

# ── Hạt giống ngẫu nhiên — để kết quả có thể tái tạo ───────────────────────
SEED = 42
np.random.seed(SEED)
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

# ── GPU Detection ────────────────────────────────────────────────────────────
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"🖥️ PyTorch Device: {DEVICE}")
if torch.cuda.is_available():
    for i in range(torch.cuda.device_count()):
        print(f"   GPU {i}: {torch.cuda.get_device_name(i)}")

# ── Thư mục xuất mô hình ────────────────────────────────────────────────────
OUTPUT_DIR = "/kaggle/working"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── 4 lớp tấn công tập trung ────────────────────────────────────────────────
TARGET_CLASSES = ["Benign", "DoS", "DDoS", "PortScan"]
NUM_CLASSES = len(TARGET_CLASSES)

# ── 77 đặc trưng chuẩn CICFlowMeter ────────────────────────────────────────
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

# ── Ánh xạ tên cột từ CICIDS2017 sang chuẩn ────────────────────────────────
MAP_CICIDS2017 = {
    ' Total Length of Fwd Packets': 'Fwd Packets Length Total',
    'Total Length of Fwd Packets': 'Fwd Packets Length Total',
    ' Total Length of Bwd Packets': 'Bwd Packets Length Total',
    'Total Length of Bwd Packets': 'Bwd Packets Length Total',
    ' Min Packet Length': 'Packet Length Min',
    'Min Packet Length': 'Packet Length Min',
    ' Max Packet Length': 'Packet Length Max',
    'Max Packet Length': 'Packet Length Max',
    ' Average Packet Size': 'Avg Packet Size',
    'Average Packet Size': 'Avg Packet Size',
    'Init_Win_bytes_forward': 'Init Fwd Win Bytes',
    ' Init_Win_bytes_forward': 'Init Fwd Win Bytes',
    'Init_Win_bytes_backward': 'Init Bwd Win Bytes',
    ' Init_Win_bytes_backward': 'Init Bwd Win Bytes',
    'act_data_pkt_fwd': 'Fwd Act Data Packets',
    ' act_data_pkt_fwd': 'Fwd Act Data Packets',
    'min_seg_size_forward': 'Fwd Seg Size Min',
    ' min_seg_size_forward': 'Fwd Seg Size Min',
    ' Destination Port': 'Destination Port',
    ' Protocol': 'Protocol',
    ' Flow Duration': 'Flow Duration',
    ' Total Fwd Packets': 'Total Fwd Packets',
    ' Total Backward Packets': 'Total Backward Packets',
    ' Fwd Packet Length Max': 'Fwd Packet Length Max',
    ' Fwd Packet Length Min': 'Fwd Packet Length Min',
    ' Fwd Packet Length Mean': 'Fwd Packet Length Mean',
    ' Fwd Packet Length Std': 'Fwd Packet Length Std',
    ' Bwd Packet Length Max': 'Bwd Packet Length Max',
    ' Bwd Packet Length Min': 'Bwd Packet Length Min',
    ' Bwd Packet Length Mean': 'Bwd Packet Length Mean',
    ' Bwd Packet Length Std': 'Bwd Packet Length Std',
    ' Flow Bytes/s': 'Flow Bytes/s',
    ' Flow Packets/s': 'Flow Packets/s',
    ' Flow IAT Mean': 'Flow IAT Mean',
    ' Flow IAT Std': 'Flow IAT Std',
    ' Flow IAT Max': 'Flow IAT Max',
    ' Flow IAT Min': 'Flow IAT Min',
    ' Fwd IAT Total': 'Fwd IAT Total',
    ' Fwd IAT Mean': 'Fwd IAT Mean',
    ' Fwd IAT Std': 'Fwd IAT Std',
    ' Fwd IAT Max': 'Fwd IAT Max',
    ' Fwd IAT Min': 'Fwd IAT Min',
    ' Bwd IAT Total': 'Bwd IAT Total',
    ' Bwd IAT Mean': 'Bwd IAT Mean',
    ' Bwd IAT Std': 'Bwd IAT Std',
    ' Bwd IAT Max': 'Bwd IAT Max',
    ' Bwd IAT Min': 'Bwd IAT Min',
    ' Fwd PSH Flags': 'Fwd PSH Flags',
    ' Bwd PSH Flags': 'Bwd PSH Flags',
    ' Fwd URG Flags': 'Fwd URG Flags',
    ' Bwd URG Flags': 'Bwd URG Flags',
    ' Fwd Header Length': 'Fwd Header Length',
    ' Bwd Header Length': 'Bwd Header Length',
    ' Fwd Packets/s': 'Fwd Packets/s',
    ' Bwd Packets/s': 'Bwd Packets/s',
    ' Packet Length Mean': 'Packet Length Mean',
    ' Packet Length Std': 'Packet Length Std',
    ' Packet Length Variance': 'Packet Length Variance',
    ' FIN Flag Count': 'FIN Flag Count',
    ' SYN Flag Count': 'SYN Flag Count',
    ' RST Flag Count': 'RST Flag Count',
    ' PSH Flag Count': 'PSH Flag Count',
    ' ACK Flag Count': 'ACK Flag Count',
    ' URG Flag Count': 'URG Flag Count',
    ' CWE Flag Count': 'CWE Flag Count',
    ' ECE Flag Count': 'ECE Flag Count',
    ' Down/Up Ratio': 'Down/Up Ratio',
    ' Avg Fwd Segment Size': 'Avg Fwd Segment Size',
    ' Avg Bwd Segment Size': 'Avg Bwd Segment Size',
    ' Fwd Avg Bytes/Bulk': 'Fwd Avg Bytes/Bulk',
    ' Fwd Avg Packets/Bulk': 'Fwd Avg Packets/Bulk',
    ' Fwd Avg Bulk Rate': 'Fwd Avg Bulk Rate',
    ' Bwd Avg Bytes/Bulk': 'Bwd Avg Bytes/Bulk',
    ' Bwd Avg Packets/Bulk': 'Bwd Avg Packets/Bulk',
    ' Bwd Avg Bulk Rate': 'Bwd Avg Bulk Rate',
    ' Subflow Fwd Packets': 'Subflow Fwd Packets',
    ' Subflow Fwd Bytes': 'Subflow Fwd Bytes',
    ' Subflow Bwd Packets': 'Subflow Bwd Packets',
    ' Subflow Bwd Bytes': 'Subflow Bwd Bytes',
    ' Active Mean': 'Active Mean',
    ' Active Std': 'Active Std',
    ' Active Max': 'Active Max',
    ' Active Min': 'Active Min',
    ' Idle Mean': 'Idle Mean',
    ' Idle Std': 'Idle Std',
    ' Idle Max': 'Idle Max',
    ' Idle Min': 'Idle Min',
    ' Label': 'Label',
}

# ── Ánh xạ tên cột từ CSE-CIC-IDS2018 sang chuẩn ───────────────────────────
MAP_CICIDS2018 = {
    'Dst Port': 'Destination Port',
    'Tot Fwd Pkts': 'Total Fwd Packets',
    'Tot Bwd Pkts': 'Total Backward Packets',
    'TotLen Fwd Pkts': 'Fwd Packets Length Total',
    'TotLen Bwd Pkts': 'Bwd Packets Length Total',
    'Fwd Pkt Len Max': 'Fwd Packet Length Max',
    'Fwd Pkt Len Min': 'Fwd Packet Length Min',
    'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
    'Fwd Pkt Len Std': 'Fwd Packet Length Std',
    'Bwd Pkt Len Max': 'Bwd Packet Length Max',
    'Bwd Pkt Len Min': 'Bwd Packet Length Min',
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
    'Bwd Pkt Len Std': 'Bwd Packet Length Std',
    'Flow Byts/s': 'Flow Bytes/s',
    'Flow Pkts/s': 'Flow Packets/s',
    'Fwd IAT Tot': 'Fwd IAT Total',
    'Bwd IAT Tot': 'Bwd IAT Total',
    'Fwd Header Len': 'Fwd Header Length',
    'Bwd Header Len': 'Bwd Header Length',
    'Fwd Pkts/s': 'Fwd Packets/s',
    'Bwd Pkts/s': 'Bwd Packets/s',
    'Pkt Len Min': 'Packet Length Min',
    'Pkt Len Max': 'Packet Length Max',
    'Pkt Len Mean': 'Packet Length Mean',
    'Pkt Len Std': 'Packet Length Std',
    'Pkt Len Var': 'Packet Length Variance',
    'FIN Flag Cnt': 'FIN Flag Count',
    'SYN Flag Cnt': 'SYN Flag Count',
    'RST Flag Cnt': 'RST Flag Count',
    'PSH Flag Cnt': 'PSH Flag Count',
    'ACK Flag Cnt': 'ACK Flag Count',
    'URG Flag Cnt': 'URG Flag Count',
    'ECE Flag Cnt': 'ECE Flag Count',
    'CWE Flag Count': 'CWE Flag Count',
    'Pkt Size Avg': 'Avg Packet Size',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
    'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
    'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate',
    'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
    'Subflow Fwd Pkts': 'Subflow Fwd Packets',
    'Subflow Fwd Byts': 'Subflow Fwd Bytes',
    'Subflow Bwd Pkts': 'Subflow Bwd Packets',
    'Subflow Bwd Byts': 'Subflow Bwd Bytes',
    'Init Fwd Win Byts': 'Init Fwd Win Bytes',
    'Init Bwd Win Byts': 'Init Bwd Win Bytes',
    'Fwd Act Data Pkts': 'Fwd Act Data Packets',
    'Fwd Seg Size Min': 'Fwd Seg Size Min',
}

# ── Bản đồ ánh xạ nhãn gốc → nhãn phân loại cấp cao ────────────────────────
LABEL_CATEGORY_MAP = {
    # Benign
    'BENIGN': 'Benign',
    'Benign': 'Benign',
    # DoS (từ CICIDS2017)
    'DoS Hulk': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'DoS_Hulk': 'DoS',
    'DoS_GoldenEye': 'DoS',
    'DoS_slowloris': 'DoS',
    'DoS_Slowhttptest': 'DoS',
    # DoS (từ CSE-CIC-IDS2018)
    'DoS attacks-Hulk': 'DoS',
    'DoS attacks-GoldenEye': 'DoS',
    'DoS attacks-Slowloris': 'DoS',
    'DoS attacks-SlowHTTPTest': 'DoS',
    # DDoS
    'DDoS': 'DDoS',
    'DDoS attack-HOIC': 'DDoS',
    'DDoS attack-LOIC-UDP': 'DDoS',
    'DDoS attacks-LOIC-HTTP': 'DDoS',
    'DDoS attack-LOIC-HTTP': 'DDoS',
    'DDOS attack-HOIC': 'DDoS',
    'DDOS attack-LOIC-UDP': 'DDoS',
    'DrDoS_DNS': 'DDoS',
    # PortScan
    'PortScan': 'PortScan',
    # Brute Force (từ CSE-CIC-IDS2018 — loại bỏ, không thuộc 4 lớp mục tiêu)
    'FTP-BruteForce': 'BruteForce',
    'SSH-Bruteforce': 'BruteForce',
    'FTP-Patator': 'BruteForce',
    'SSH-Patator': 'BruteForce',
    'Brute Force -Web': 'BruteForce',
    'Brute Force -XSS': 'BruteForce',
    # Bot
    'Bot': 'Botnet',
    'Botnet': 'Botnet',
    # Web Attack
    'Web Attack \x96 Brute Force': 'Web_Attack',
    'Web Attack \x96 XSS': 'Web_Attack',
    'Web Attack \x96 Sql Injection': 'Web_Attack',
    'Web_Attack_Brute_Force': 'Web_Attack',
    'Web_Attack_XSS': 'Web_Attack',
    'Web_Attack_Sql_Injection': 'Web_Attack',
    'SQL Injection': 'Web_Attack',
    # Infiltration / Heartbleed
    'Infiltration': 'Infiltration',
    'Infilteration': 'Infiltration',
    'Heartbleed': 'Heartbleed',
}

print("Cấu hình xong. Số đặc trưng:", len(FEATURE_COLS))
print("4 lớp phân loại:", TARGET_CLASSES)
print("XGBoost version:", xgb.__version__)
print("PyTorch version:", torch.__version__)


# %%
# ============================================================================
# CELL 3 — Đọc dữ liệu trực tiếp từ 2 Kaggle Datasets: CICIDS2017 & 2018
# ============================================================================

def find_csv_files(base_dir, pattern_keywords):
    """Tìm tất cả file CSV trong base_dir có chứa keyword trong đường dẫn."""
    all_csvs = glob.glob(os.path.join(base_dir, "**", "*.csv"), recursive=True)
    matched = []
    for csv_path in all_csvs:
        path_lower = csv_path.lower()
        if any(kw in path_lower for kw in pattern_keywords):
            matched.append(csv_path)
    return sorted(matched)


def load_cicids2017_from_kaggle():
    """
    Đọc CICIDS2017 từ Kaggle Datasets.
    Dataset thường chứa nhiều file CSV (Monday, Tuesday, ..., Friday).
    """
    print("\n" + "=" * 70)
    print("📂 ĐANG ĐỌC CICIDS2017 TỪ KAGGLE DATASETS...")
    print("=" * 70)

    # Tìm tất cả CSV liên quan đến CICIDS2017
    search_dirs = glob.glob("/kaggle/input/*cicids*", recursive=False) + \
                  glob.glob("/kaggle/input/*CICIDS*", recursive=False) + \
                  glob.glob("/kaggle/input/*intrusion*", recursive=False) + \
                  glob.glob("/kaggle/input/*network*intrusion*", recursive=False)

    csv_files = []
    for d in search_dirs:
        if os.path.isdir(d):
            csv_files.extend(glob.glob(os.path.join(d, "**", "*.csv"), recursive=True))
        elif d.endswith('.csv'):
            csv_files.append(d)

    # Thêm tìm kiếm rộng hơn nếu chưa tìm thấy
    if not csv_files:
        csv_files = glob.glob("/kaggle/input/**/*.csv", recursive=True)
        # Lọc chỉ giữ file liên quan 2017
        csv_files = [f for f in csv_files if any(kw in f.lower()
                     for kw in ['2017', 'cicids', 'monday', 'tuesday', 'wednesday',
                                'thursday', 'friday', 'intrusion'])]

    # Loại bỏ file 2018
    csv_files = [f for f in csv_files if '2018' not in f and 'cse' not in f.lower()]

    print(f"   Tìm thấy {len(csv_files)} file CSV cho CICIDS2017:")
    for f in csv_files:
        print(f"   - {f}")

    if not csv_files:
        print("   ⚠️ Không tìm thấy file CICIDS2017! Kiểm tra lại tên dataset trên Kaggle.")
        return pd.DataFrame()

    frames = []
    for csv_path in csv_files:
        try:
            print(f"   Đang đọc: {os.path.basename(csv_path)}...")
            df = pd.read_csv(csv_path, low_memory=False, encoding='utf-8',
                             on_bad_lines='skip')
            # Chuẩn hoá tên cột (bỏ khoảng trắng thừa đầu/cuối, rồi map)
            df.columns = [c.strip() for c in df.columns]
            df = df.rename(columns={k.strip(): v for k, v in MAP_CICIDS2017.items()})

            # Tạo Protocol nếu thiếu
            if 'Protocol' not in df.columns:
                if 'Destination Port' in df.columns:
                    df['Protocol'] = np.where(
                        pd.to_numeric(df['Destination Port'], errors='coerce') == 53, 17, 6
                    )
                else:
                    df['Protocol'] = 6

            # Đảm bảo có cột Label
            if 'Label' not in df.columns:
                # Thử tìm cột label với tên khác
                label_cols = [c for c in df.columns if 'label' in c.lower()]
                if label_cols:
                    df = df.rename(columns={label_cols[0]: 'Label'})
                else:
                    print(f"   ⚠️ Bỏ qua {csv_path}: không có cột Label")
                    continue

            df['Label'] = df['Label'].astype(str).str.strip()
            # Loại bỏ dòng header bị lẫn vào data
            df = df[df['Label'] != 'Label']

            frames.append(df)
            print(f"      → {len(df):,} dòng | Nhãn: {df['Label'].nunique()} loại")
        except Exception as e:
            print(f"   ❌ Lỗi đọc {csv_path}: {e}")

    if not frames:
        return pd.DataFrame()

    df_2017 = pd.concat(frames, ignore_index=True)
    print(f"\n   ✅ Tổng CICIDS2017: {len(df_2017):,} dòng")
    print("   Phân bố nhãn:")
    print(df_2017['Label'].value_counts().to_string())
    return df_2017


def load_cicids2018_from_kaggle():
    """
    Đọc CSE-CIC-IDS2018 từ Kaggle Datasets.
    Dataset thường chứa nhiều file CSV theo ngày.
    """
    print("\n" + "=" * 70)
    print("📂 ĐANG ĐỌC CSE-CIC-IDS2018 TỪ KAGGLE DATASETS...")
    print("=" * 70)

    # Tìm thư mục 2018
    search_dirs = glob.glob("/kaggle/input/*2018*", recursive=False) + \
                  glob.glob("/kaggle/input/*cse*", recursive=False) + \
                  glob.glob("/kaggle/input/*ids*intrusion*", recursive=False)

    csv_files = []
    for d in search_dirs:
        if os.path.isdir(d):
            csv_files.extend(glob.glob(os.path.join(d, "**", "*.csv"), recursive=True))
        elif d.endswith('.csv'):
            csv_files.append(d)

    # Loại bỏ file 2017
    csv_files = [f for f in csv_files if '2017' not in f]

    print(f"   Tìm thấy {len(csv_files)} file CSV cho CSE-CIC-IDS2018:")
    for f in csv_files:
        print(f"   - {f}")

    if not csv_files:
        print("   ⚠️ Không tìm thấy file CSE-CIC-IDS2018! Kiểm tra lại tên dataset.")
        return pd.DataFrame()

    frames = []
    for csv_path in csv_files:
        try:
            print(f"   Đang đọc: {os.path.basename(csv_path)}...")
            df = pd.read_csv(csv_path, low_memory=False, encoding='utf-8',
                             on_bad_lines='skip')
            df.columns = [c.strip() for c in df.columns]
            df = df.rename(columns=MAP_CICIDS2018)

            # Tìm cột Label
            if 'Label' not in df.columns:
                label_cols = [c for c in df.columns if 'label' in c.lower()]
                if label_cols:
                    df = df.rename(columns={label_cols[0]: 'Label'})
                else:
                    print(f"   ⚠️ Bỏ qua {csv_path}: không có cột Label")
                    continue

            df['Label'] = df['Label'].astype(str).str.strip()
            df = df[df['Label'] != 'Label']

            # Tạo Protocol nếu thiếu
            if 'Protocol' not in df.columns:
                if 'Destination Port' in df.columns:
                    df['Protocol'] = np.where(
                        pd.to_numeric(df['Destination Port'], errors='coerce') == 53, 17, 6
                    )
                else:
                    df['Protocol'] = 6

            frames.append(df)
            print(f"      → {len(df):,} dòng | Nhãn: {df['Label'].nunique()} loại")
        except Exception as e:
            print(f"   ❌ Lỗi đọc {csv_path}: {e}")

    if not frames:
        return pd.DataFrame()

    df_2018 = pd.concat(frames, ignore_index=True)
    print(f"\n   ✅ Tổng CSE-CIC-IDS2018: {len(df_2018):,} dòng")
    print("   Phân bố nhãn:")
    print(df_2018['Label'].value_counts().to_string())
    return df_2018


# ── Đọc cả 2 dataset ────────────────────────────────────────────────────────
print("Liệt kê nội dung /kaggle/input/:")
if os.path.exists("/kaggle/input"):
    for item in os.listdir("/kaggle/input"):
        item_path = os.path.join("/kaggle/input", item)
        if os.path.isdir(item_path):
            n_files = sum(1 for _ in glob.glob(os.path.join(item_path, "**", "*"), recursive=True)
                          if os.path.isfile(_))
            print(f"   📁 {item}/ ({n_files} files)")
        else:
            print(f"   📄 {item}")
else:
    print("   ⚠️ /kaggle/input không tồn tại — bạn đang chạy ngoài Kaggle?")

df_2017 = load_cicids2017_from_kaggle()
df_2018 = load_cicids2018_from_kaggle()


# %%
# ============================================================================
# CELL 4 — Gộp, chuẩn hoá nhãn, lọc 4 lớp, lấy mẫu cân bằng
# ============================================================================

print("\n" + "=" * 70)
print("📊 GỘP VÀ CHUẨN HOÁ DỮ LIỆU...")
print("=" * 70)

# Gộp 2 dataset
dfs_to_merge = [d for d in [df_2017, df_2018] if not d.empty]
if not dfs_to_merge:
    raise RuntimeError("❌ Không có dữ liệu nào được đọc thành công!")

df_raw = pd.concat(dfs_to_merge, ignore_index=True)
print(f"Tổng số dòng sau gộp: {len(df_raw):,}")

# Ánh xạ nhãn gốc → Label_Category
df_raw['Label_Category'] = df_raw['Label'].map(
    lambda x: LABEL_CATEGORY_MAP.get(x.strip(), 'Other')
)
print("\nPhân bố Label_Category sau ánh xạ:")
print(df_raw['Label_Category'].value_counts().to_string())

# Lọc chỉ giữ 4 lớp mục tiêu
df = df_raw[df_raw['Label_Category'].isin(TARGET_CLASSES)].copy()
df = df.reset_index(drop=True)
print(f"\nSau khi lọc 4 lớp: {len(df):,} dòng")
dist_raw = df['Label_Category'].value_counts()
print(dist_raw.to_string())

# ── Chiến lược lấy mẫu thông minh ───────────────────────────────────────────
# Lấy tối đa mỗi lớp, giới hạn lớp quá lớn để tránh mất cân bằng nặng
MAX_PER_CLASS = 50_000  # Tăng lên so với trước để DNN có đủ dữ liệu học

sampled_frames = []
for cls in TARGET_CLASSES:
    cls_df = df[df['Label_Category'] == cls]
    take = min(len(cls_df), MAX_PER_CLASS)
    sampled_frames.append(cls_df.sample(n=take, random_state=SEED))
    print(f"   {cls:12s}: lấy {take:,} / {len(cls_df):,} mẫu")

df_bal = pd.concat(sampled_frames, ignore_index=True)
df_bal = df_bal.sample(frac=1, random_state=SEED).reset_index(drop=True)

print(f"\n✅ Tổng mẫu sau lấy mẫu: {len(df_bal):,}")
print("   Phân bố cuối:")
print(df_bal['Label_Category'].value_counts().to_string())


# %%
# ============================================================================
# CELL 5 — Chuẩn bị ma trận X, nhãn y, StandardScaler, sample weights
# ============================================================================

# Lấy các cột đặc trưng có trong dữ liệu
avail_features = [c for c in FEATURE_COLS if c in df_bal.columns]
missing = [c for c in FEATURE_COLS if c not in df_bal.columns]
if missing:
    print(f"⚠️ Các cột sau không có trong dataset (sẽ điền 0): {missing}")
    for col in missing:
        df_bal[col] = 0.0
    avail_features = FEATURE_COLS  # Giờ đã có đủ

X_raw = df_bal[avail_features].copy()

# Chuyển sang số, thay inf/NaN bằng 0
for col in X_raw.columns:
    X_raw[col] = pd.to_numeric(X_raw[col], errors='coerce')
X_raw = X_raw.replace([np.inf, -np.inf], np.nan).fillna(0.0)
X_raw = X_raw.values.astype(np.float32)

print(f"✅ X shape (raw): {X_raw.shape}")

# ── StandardScaler — chuẩn hoá cho DNN ──────────────────────────────────────
# XGBoost không cần scale, nhưng DNN cần StandardScaler để hội tụ nhanh
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_raw).astype(np.float32)
print(f"✅ X shape (scaled): {X_scaled.shape}")

# Lưu scaler để inference
scaler_path = os.path.join(OUTPUT_DIR, "standard_scaler.pkl")
with open(scaler_path, "wb") as f:
    pickle.dump(scaler, f)
print(f"✅ Đã lưu StandardScaler → {scaler_path}")

# ── Encode nhãn ─────────────────────────────────────────────────────────────
le = LabelEncoder()
le.fit(TARGET_CLASSES)
y = le.transform(df_bal['Label_Category'])

print("\n   Mapping nhãn:")
for i, cls in enumerate(le.classes_):
    count = int((y == i).sum())
    print(f"   {i} → {cls:12s}: {count:,} mẫu")

# Lưu label encoder
le_path = os.path.join(OUTPUT_DIR, "label_encoder_multiclass.pkl")
with open(le_path, "wb") as f:
    pickle.dump(le, f)
print(f"\n✅ Đã lưu label encoder → {le_path}")

# ── Sample weights ──────────────────────────────────────────────────────────
sample_weights = compute_sample_weight(class_weight="balanced", y=y)
print("\n✅ Sample weights đã tính:")
for i, cls in enumerate(le.classes_):
    avg_w = sample_weights[y == i].mean()
    print(f"   {cls:12s} → avg weight = {avg_w:.4f}")

# ── Class weights cho DNN (PyTorch CrossEntropyLoss) ────────────────────────
class_weights_np = compute_class_weight(class_weight="balanced", classes=np.arange(NUM_CLASSES), y=y)
class_weights_tensor = torch.FloatTensor(class_weights_np).to(DEVICE)
print("\n✅ Class weights cho DNN:")
for i, cls in enumerate(le.classes_):
    print(f"   {cls:12s} → weight = {class_weights_np[i]:.4f}")


# %%
# ============================================================================
# CELL 6 — Định nghĩa Deep Neural Network (DNN) với Residual Blocks
# ============================================================================
# Kiến trúc: Input(77) → [ResBlock×4] → Output(4 classes)
# Mỗi ResBlock: Linear → BatchNorm → GELU → Dropout → Linear → BatchNorm → GELU → Dropout + Skip Connection
# Tổng > 500K parameters — đủ sâu để học pattern phức tạp trong network traffic

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
        return self.dropout(self.act(self.block(x) + x))  # Skip connection


class NIDSDeepNet(nn.Module):
    """
    Deep Neural Network cho Network Intrusion Detection.

    Kiến trúc:
    - Input Projection: 77 features → 512 dims (với BatchNorm + GELU)
    - 4 Residual Blocks (512 dims mỗi block)
    - Feature Squeeze: 512 → 256 → 128
    - Classification Head: 128 → 4 classes

    Tổng tham số: ~1.5M (đủ capacity để học deep patterns)
    """
    def __init__(self, input_dim=77, num_classes=4, hidden_dim=512, n_blocks=4, dropout=0.3):
        super().__init__()

        # Input projection
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout * 0.5),  # Dropout nhẹ hơn ở input
        )

        # Residual blocks
        self.res_blocks = nn.Sequential(
            *[ResidualBlock(hidden_dim, dropout) for _ in range(n_blocks)]
        )

        # Feature squeeze (giảm chiều dần)
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

        # Classification head
        self.classifier = nn.Linear(hidden_dim // 4, num_classes)

        # Khởi tạo trọng số
        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)
            elif isinstance(m, nn.BatchNorm1d):
                nn.init.constant_(m.weight, 1)
                nn.init.constant_(m.bias, 0)

    def forward(self, x):
        x = self.input_proj(x)
        x = self.res_blocks(x)
        x = self.squeeze(x)
        logits = self.classifier(x)
        return logits

    def predict_proba(self, x):
        """Trả về xác suất softmax cho mỗi lớp."""
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            return torch.softmax(logits, dim=-1)


# In thông tin mô hình
_test_model = NIDSDeepNet(input_dim=len(avail_features), num_classes=NUM_CLASSES)
total_params = sum(p.numel() for p in _test_model.parameters())
trainable_params = sum(p.numel() for p in _test_model.parameters() if p.requires_grad)
print(f"\n🧠 NIDSDeepNet Architecture:")
print(f"   Input dim:  {len(avail_features)}")
print(f"   Hidden dim: 512")
print(f"   Res blocks: 4")
print(f"   Total params:     {total_params:,}")
print(f"   Trainable params: {trainable_params:,}")
print(_test_model)
del _test_model


# %%
# ============================================================================
# CELL 7 — Hàm huấn luyện DNN (1 fold)
# ============================================================================

def train_dnn_fold(X_tr, y_tr, X_val, y_val, class_weights, fold_idx,
                   epochs=80, batch_size=2048, lr=1e-3, patience=15):
    """
    Huấn luyện DNN trên 1 fold với:
    - OneCycleLR scheduler (warm-up + cosine annealing)
    - Early stopping trên validation loss
    - Class-weighted CrossEntropyLoss
    - Mixed Precision Training (AMP) cho tốc độ GPU
    """
    print(f"\n  🔧 DNN Fold {fold_idx}: Training {len(X_tr):,} samples, "
          f"validating {len(X_val):,} samples...")

    # Tạo DataLoaders
    train_dataset = TensorDataset(
        torch.FloatTensor(X_tr),
        torch.LongTensor(y_tr)
    )
    val_dataset = TensorDataset(
        torch.FloatTensor(X_val),
        torch.LongTensor(y_val)
    )

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True,
                              num_workers=2, pin_memory=True, drop_last=False)
    val_loader = DataLoader(val_dataset, batch_size=batch_size * 2, shuffle=False,
                            num_workers=2, pin_memory=True)

    # Khởi tạo model
    model = NIDSDeepNet(
        input_dim=X_tr.shape[1],
        num_classes=NUM_CLASSES,
        hidden_dim=512,
        n_blocks=4,
        dropout=0.3,
    ).to(DEVICE)

    # Loss, optimizer, scheduler
    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.OneCycleLR(
        optimizer, max_lr=lr, steps_per_epoch=len(train_loader),
        epochs=epochs, pct_start=0.1, anneal_strategy='cos'
    )

    # Mixed Precision (AMP)
    scaler_amp = torch.amp.GradScaler('cuda') if DEVICE.type == 'cuda' else None

    # Early stopping
    best_val_loss = float('inf')
    best_model_state = None
    patience_counter = 0

    for epoch in range(1, epochs + 1):
        # ── Training ─────────────────────────────────────────────────────
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0

        for batch_X, batch_y in train_loader:
            batch_X = batch_X.to(DEVICE, non_blocking=True)
            batch_y = batch_y.to(DEVICE, non_blocking=True)

            optimizer.zero_grad(set_to_none=True)

            if scaler_amp is not None:
                with torch.amp.autocast('cuda'):
                    logits = model(batch_X)
                    loss = criterion(logits, batch_y)
                scaler_amp.scale(loss).backward()
                scaler_amp.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                scaler_amp.step(optimizer)
                scaler_amp.update()
            else:
                logits = model(batch_X)
                loss = criterion(logits, batch_y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()

            scheduler.step()

            train_loss += loss.item() * batch_X.size(0)
            train_correct += (logits.argmax(dim=1) == batch_y).sum().item()
            train_total += batch_X.size(0)

        avg_train_loss = train_loss / train_total
        train_acc = train_correct / train_total

        # ── Validation ───────────────────────────────────────────────────
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0

        with torch.no_grad():
            for batch_X, batch_y in val_loader:
                batch_X = batch_X.to(DEVICE, non_blocking=True)
                batch_y = batch_y.to(DEVICE, non_blocking=True)

                if scaler_amp is not None:
                    with torch.amp.autocast('cuda'):
                        logits = model(batch_X)
                        loss = criterion(logits, batch_y)
                else:
                    logits = model(batch_X)
                    loss = criterion(logits, batch_y)

                val_loss += loss.item() * batch_X.size(0)
                val_correct += (logits.argmax(dim=1) == batch_y).sum().item()
                val_total += batch_X.size(0)

        avg_val_loss = val_loss / val_total
        val_acc = val_correct / val_total

        # Log mỗi 10 epoch hoặc epoch cuối
        if epoch % 10 == 0 or epoch == 1 or epoch == epochs:
            current_lr = scheduler.get_last_lr()[0]
            print(f"    Epoch {epoch:3d}/{epochs} | "
                  f"TrainLoss={avg_train_loss:.4f} TrainAcc={train_acc:.4f} | "
                  f"ValLoss={avg_val_loss:.4f} ValAcc={val_acc:.4f} | "
                  f"LR={current_lr:.2e}")

        # Early stopping
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            best_model_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"    ⏹️ Early stopping tại epoch {epoch} "
                      f"(best val_loss = {best_val_loss:.4f})")
                break

    # Load best model
    model.load_state_dict(best_model_state)
    model.to(DEVICE)

    # Dự đoán validation
    model.eval()
    all_probs = []
    with torch.no_grad():
        for batch_X, _ in val_loader:
            batch_X = batch_X.to(DEVICE, non_blocking=True)
            probs = torch.softmax(model(batch_X), dim=-1)
            all_probs.append(probs.cpu().numpy())

    val_probs = np.concatenate(all_probs, axis=0)

    return model, val_probs, best_val_loss


# %%
# ============================================================================
# CELL 8 — Stratified 4-Fold CV: XGBoost + DNN Ensemble
# ============================================================================

skf = StratifiedKFold(n_splits=4, shuffle=True, random_state=SEED)

# Kết quả cho từng model
xgb_fold_results = []
dnn_fold_results = []
ensemble_fold_results = []

best_xgb_model = None
best_dnn_model = None
best_ensemble_f1 = -1.0

all_y_true = []
all_y_pred_xgb = []
all_y_pred_dnn = []
all_y_pred_ens = []
all_y_prob_xgb = []
all_y_prob_dnn = []
all_y_prob_ens = []

# Trọng số Ensemble: XGBoost thường mạnh hơn với tabular data, DNN bổ trợ
ENSEMBLE_W_XGB = 0.55
ENSEMBLE_W_DNN = 0.45

XGB_PARAMS = dict(
    objective         = "multi:softprob",
    num_class         = NUM_CLASSES,
    eval_metric       = ["mlogloss", "merror"],
    tree_method       = "hist",
    device            = "cuda",
    n_estimators      = 1500,
    learning_rate     = 0.05,
    max_depth         = 6,
    subsample         = 0.8,
    colsample_bytree  = 0.8,
    reg_alpha         = 0.1,
    reg_lambda        = 1.0,
    min_child_weight  = 5,
    gamma             = 0.1,
    random_state      = SEED,
    n_jobs            = -1,
    verbosity         = 0,
    early_stopping_rounds = 20,
)

print("=" * 70)
print("🚀 BẮT ĐẦU HYBRID TRAINING: XGBoost + DNN (4-Fold CV)")
print(f"   Ensemble weights: XGBoost={ENSEMBLE_W_XGB}, DNN={ENSEMBLE_W_DNN}")
print("=" * 70)

for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X_raw, y), start=1):
    print(f"\n{'═' * 70}")
    print(f"  📌 FOLD {fold_idx}/4")
    print(f"{'═' * 70}")

    # Dữ liệu: XGBoost dùng X_raw, DNN dùng X_scaled
    X_tr_raw, X_val_raw = X_raw[train_idx], X_raw[val_idx]
    X_tr_sc, X_val_sc   = X_scaled[train_idx], X_scaled[val_idx]
    y_tr, y_val         = y[train_idx], y[val_idx]
    sw_tr               = sample_weights[train_idx]

    # ── 1. XGBoost ───────────────────────────────────────────────────────
    print(f"\n  🌲 XGBoost Training...")
    xgb_model = xgb.XGBClassifier(**XGB_PARAMS)
    xgb_model.fit(
        X_tr_raw, y_tr,
        sample_weight=sw_tr,
        eval_set=[(X_val_raw, y_val)],
        verbose=False,
    )

    xgb_probs = xgb_model.predict_proba(X_val_raw)
    xgb_preds = np.argmax(xgb_probs, axis=1)
    xgb_acc = accuracy_score(y_val, xgb_preds)
    xgb_f1 = f1_score(y_val, xgb_preds, average="macro")
    xgb_ll = log_loss(y_val, xgb_probs)

    print(f"  🌲 XGBoost Fold {fold_idx}: Acc={xgb_acc:.4f}  "
          f"F1={xgb_f1:.4f}  LogLoss={xgb_ll:.4f}  "
          f"BestIter={xgb_model.best_iteration}")

    xgb_fold_results.append({
        "fold": fold_idx,
        "accuracy": round(xgb_acc, 6),
        "f1_macro": round(xgb_f1, 6),
        "log_loss": round(xgb_ll, 6),
        "best_iteration": xgb_model.best_iteration,
    })

    # ── 2. DNN ───────────────────────────────────────────────────────────
    print(f"\n  🧠 DNN Training...")
    dnn_model, dnn_probs, dnn_best_loss = train_dnn_fold(
        X_tr_sc, y_tr, X_val_sc, y_val,
        class_weights=class_weights_tensor,
        fold_idx=fold_idx,
        epochs=80,
        batch_size=2048,
        lr=1e-3,
        patience=15,
    )

    dnn_preds = np.argmax(dnn_probs, axis=1)
    dnn_acc = accuracy_score(y_val, dnn_preds)
    dnn_f1 = f1_score(y_val, dnn_preds, average="macro")
    dnn_ll = log_loss(y_val, dnn_probs)

    print(f"  🧠 DNN Fold {fold_idx}: Acc={dnn_acc:.4f}  "
          f"F1={dnn_f1:.4f}  LogLoss={dnn_ll:.4f}")

    dnn_fold_results.append({
        "fold": fold_idx,
        "accuracy": round(dnn_acc, 6),
        "f1_macro": round(dnn_f1, 6),
        "log_loss": round(dnn_ll, 6),
    })

    # ── 3. Ensemble ──────────────────────────────────────────────────────
    ens_probs = ENSEMBLE_W_XGB * xgb_probs + ENSEMBLE_W_DNN * dnn_probs
    ens_preds = np.argmax(ens_probs, axis=1)
    ens_acc = accuracy_score(y_val, ens_preds)
    ens_f1 = f1_score(y_val, ens_preds, average="macro")
    ens_ll = log_loss(y_val, ens_probs)

    # Phân tích độ tự tin
    max_conf = ens_probs.max(axis=1)
    high_conf_mask = max_conf >= 0.85
    high_conf_acc = accuracy_score(y_val[high_conf_mask], ens_preds[high_conf_mask]) \
                    if high_conf_mask.sum() > 0 else float("nan")
    high_conf_pct = high_conf_mask.mean() * 100

    print(f"\n  🎯 ENSEMBLE Fold {fold_idx}: Acc={ens_acc:.4f}  "
          f"F1={ens_f1:.4f}  LogLoss={ens_ll:.4f}  "
          f"HighConf≥85%={high_conf_pct:.1f}% (acc={high_conf_acc:.4f})")

    ensemble_fold_results.append({
        "fold": fold_idx,
        "accuracy": round(ens_acc, 6),
        "f1_macro": round(ens_f1, 6),
        "log_loss": round(ens_ll, 6),
        "high_conf_pct": round(high_conf_pct, 2),
        "high_conf_acc": round(high_conf_acc, 6),
    })

    # Giữ model tốt nhất
    if ens_f1 > best_ensemble_f1:
        best_ensemble_f1 = ens_f1
        best_xgb_model = xgb_model
        best_dnn_model = dnn_model

    # Tích lũy kết quả
    all_y_true.extend(y_val.tolist())
    all_y_pred_xgb.extend(xgb_preds.tolist())
    all_y_pred_dnn.extend(dnn_preds.tolist())
    all_y_pred_ens.extend(ens_preds.tolist())
    all_y_prob_xgb.extend(xgb_probs.tolist())
    all_y_prob_dnn.extend(dnn_probs.tolist())
    all_y_prob_ens.extend(ens_probs.tolist())

print("\n✅ Cross Validation hoàn thành!")


# %%
# ============================================================================
# CELL 9 — Tổng hợp chỉ số đánh giá & in báo cáo so sánh
# ============================================================================

all_y_true = np.array(all_y_true)
all_y_pred_xgb = np.array(all_y_pred_xgb)
all_y_pred_dnn = np.array(all_y_pred_dnn)
all_y_pred_ens = np.array(all_y_pred_ens)
all_y_prob_xgb = np.array(all_y_prob_xgb)
all_y_prob_dnn = np.array(all_y_prob_dnn)
all_y_prob_ens = np.array(all_y_prob_ens)

def compute_metrics(y_true, y_pred, y_prob, name):
    """Tính và in các chỉ số đánh giá cho một model."""
    acc = accuracy_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred, average="macro")
    ll = log_loss(y_true, y_prob)

    y_true_bin = label_binarize(y_true, classes=list(range(NUM_CLASSES)))
    brier = np.mean([
        brier_score_loss(y_true_bin[:, i], y_prob[:, i])
        for i in range(NUM_CLASSES)
    ])

    max_conf = y_prob.max(axis=1)
    hc_mask = max_conf >= 0.85
    hc_pct = hc_mask.mean() * 100
    hc_acc = accuracy_score(y_true[hc_mask], y_pred[hc_mask]) if hc_mask.sum() > 0 else 0.0

    return {
        "name": name,
        "accuracy": acc,
        "f1_macro": f1,
        "log_loss": ll,
        "brier_score": brier,
        "high_conf_pct": hc_pct,
        "high_conf_acc": hc_acc,
    }


metrics_xgb = compute_metrics(all_y_true, all_y_pred_xgb, all_y_prob_xgb, "XGBoost")
metrics_dnn = compute_metrics(all_y_true, all_y_pred_dnn, all_y_prob_dnn, "DNN")
metrics_ens = compute_metrics(all_y_true, all_y_pred_ens, all_y_prob_ens, "Ensemble")

print("\n" + "=" * 80)
print("           SO SÁNH HIỆU SUẤT CÁC MÔ HÌNH (Trung bình 4-Fold CV)")
print("=" * 80)
print(f"{'Chỉ số':<30s} | {'XGBoost':>12s} | {'DNN':>12s} | {'Ensemble':>12s}")
print("-" * 80)
for key in ["accuracy", "f1_macro", "log_loss", "brier_score", "high_conf_pct", "high_conf_acc"]:
    fmt = ".4f" if key != "high_conf_pct" else ".1f"
    suffix = "%" if key == "high_conf_pct" else ""
    print(f"  {key:<28s} | {metrics_xgb[key]:{fmt}}{suffix:>4s} | "
          f"{metrics_dnn[key]:{fmt}}{suffix:>4s} | "
          f"{metrics_ens[key]:{fmt}}{suffix:>4s}")
print("=" * 80)

# Báo cáo per-class cho Ensemble
print("\n📊 Báo cáo phân loại chi tiết — ENSEMBLE (toàn bộ validation):")
print(classification_report(
    all_y_true, all_y_pred_ens,
    target_names=le.classes_,
    digits=4
))


# %%
# ============================================================================
# CELL 10 — Vẽ biểu đồ: 3 Confusion Matrices + Feature Importance
# ============================================================================
fig, axes = plt.subplots(2, 2, figsize=(20, 16))

def plot_cm(ax, y_true, y_pred, title, acc, f1):
    cm = confusion_matrix(y_true, y_pred)
    cm_pct = cm.astype(float) / cm.sum(axis=1, keepdims=True) * 100
    sns.heatmap(
        cm_pct, annot=True, fmt=".1f", cmap="Blues",
        xticklabels=le.classes_, yticklabels=le.classes_,
        linewidths=0.5, linecolor="gray", ax=ax
    )
    ax.set_title(f"{title}\nAcc={acc:.4f}  F1={f1:.4f}", fontsize=12)
    ax.set_xlabel("Nhãn dự đoán", fontsize=10)
    ax.set_ylabel("Nhãn thực tế", fontsize=10)

# Confusion matrices cho 3 models
plot_cm(axes[0, 0], all_y_true, all_y_pred_xgb, "XGBoost",
        metrics_xgb["accuracy"], metrics_xgb["f1_macro"])
plot_cm(axes[0, 1], all_y_true, all_y_pred_dnn, "Deep Neural Network",
        metrics_dnn["accuracy"], metrics_dnn["f1_macro"])
plot_cm(axes[1, 0], all_y_true, all_y_pred_ens, "🎯 Hybrid Ensemble",
        metrics_ens["accuracy"], metrics_ens["f1_macro"])

# Feature Importance (XGBoost Top-15)
fi_scores = best_xgb_model.get_booster().get_score(importance_type="gain")
fi_df = (
    pd.DataFrame.from_dict(fi_scores, orient="index", columns=["gain"])
    .sort_values("gain", ascending=False)
    .head(15)
)
col_map = {f"f{i}": c for i, c in enumerate(avail_features)}
fi_df.index = [col_map.get(k, k) for k in fi_df.index]

fi_df.plot(kind="barh", ax=axes[1, 1], color="steelblue", legend=False)
axes[1, 1].invert_yaxis()
axes[1, 1].set_title("Top-15 Feature Importance (XGBoost Gain)", fontsize=12)
axes[1, 1].set_xlabel("Gain", fontsize=10)
axes[1, 1].set_ylabel("")
for bar in axes[1, 1].patches:
    axes[1, 1].text(
        bar.get_width() * 1.01, bar.get_y() + bar.get_height() / 2,
        f"{bar.get_width():.0f}", va="center", fontsize=8
    )

plt.suptitle("🛡️ NIDS Hybrid Training — XGBoost + DNN Ensemble (4-Fold CV)",
             fontsize=15, fontweight='bold', y=1.01)
plt.tight_layout()
plot_path = os.path.join(OUTPUT_DIR, "training_charts.png")
plt.savefig(plot_path, dpi=150, bbox_inches="tight")
plt.show()
print(f"✅ Đã lưu biểu đồ → {plot_path}")


# %%
# ============================================================================
# CELL 11 — Vẽ biểu đồ training curves comparison
# ============================================================================
fig2, axes2 = plt.subplots(1, 3, figsize=(18, 5))

# Bar chart so sánh Accuracy
model_names = ["XGBoost", "DNN", "Ensemble"]
accs = [metrics_xgb["accuracy"], metrics_dnn["accuracy"], metrics_ens["accuracy"]]
colors = ["#2196F3", "#FF5722", "#4CAF50"]

bars = axes2[0].bar(model_names, accs, color=colors, edgecolor="white", linewidth=1.5)
axes2[0].set_title("Accuracy Comparison", fontsize=13)
axes2[0].set_ylim(min(accs) - 0.01, 1.005)
for bar, acc in zip(bars, accs):
    axes2[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
                  f"{acc:.4f}", ha="center", va="bottom", fontsize=11, fontweight="bold")

# Bar chart so sánh F1-Macro
f1s = [metrics_xgb["f1_macro"], metrics_dnn["f1_macro"], metrics_ens["f1_macro"]]
bars = axes2[1].bar(model_names, f1s, color=colors, edgecolor="white", linewidth=1.5)
axes2[1].set_title("Macro-F1 Comparison", fontsize=13)
axes2[1].set_ylim(min(f1s) - 0.01, 1.005)
for bar, f1 in zip(bars, f1s):
    axes2[1].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
                  f"{f1:.4f}", ha="center", va="bottom", fontsize=11, fontweight="bold")

# Bar chart so sánh Log-Loss (thấp hơn tốt hơn)
lls = [metrics_xgb["log_loss"], metrics_dnn["log_loss"], metrics_ens["log_loss"]]
bars = axes2[2].bar(model_names, lls, color=colors, edgecolor="white", linewidth=1.5)
axes2[2].set_title("Log-Loss Comparison (↓ lower = better)", fontsize=13)
for bar, ll in zip(bars, lls):
    axes2[2].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.0005,
                  f"{ll:.4f}", ha="center", va="bottom", fontsize=11, fontweight="bold")

plt.tight_layout()
plot2_path = os.path.join(OUTPUT_DIR, "model_comparison.png")
plt.savefig(plot2_path, dpi=150, bbox_inches="tight")
plt.show()
print(f"✅ Đã lưu biểu đồ so sánh → {plot2_path}")


# %%
# ============================================================================
# CELL 12 — Lưu mô hình tốt nhất & training_report.json
# ============================================================================

# 1. Lưu XGBoost model
xgb_model_path = os.path.join(OUTPUT_DIR, "model_nids_multiclass.json")
best_xgb_model.save_model(xgb_model_path)
print(f"✅ Đã lưu XGBoost model → {xgb_model_path}")

# 2. Lưu DNN model (PyTorch)
dnn_model_path = os.path.join(OUTPUT_DIR, "model_nids_dnn.pt")
torch.save({
    'model_state_dict': best_dnn_model.state_dict(),
    'architecture': {
        'input_dim': len(avail_features),
        'num_classes': NUM_CLASSES,
        'hidden_dim': 512,
        'n_blocks': 4,
        'dropout': 0.3,
    },
    'feature_cols': avail_features,
    'target_classes': TARGET_CLASSES,
    'ensemble_weights': {'xgboost': ENSEMBLE_W_XGB, 'dnn': ENSEMBLE_W_DNN},
}, dnn_model_path)
print(f"✅ Đã lưu DNN model → {dnn_model_path}")

# 3. Lưu feature importance CSV
fi_full = (
    pd.DataFrame.from_dict(
        best_xgb_model.get_booster().get_score(importance_type="gain"),
        orient="index", columns=["gain"]
    )
    .sort_values("gain", ascending=False)
)
fi_full.index = [col_map.get(k, k) for k in fi_full.index]
fi_csv_path = os.path.join(OUTPUT_DIR, "feature_importance_nids.csv")
fi_full.to_csv(fi_csv_path)
print(f"✅ Đã lưu feature importance → {fi_csv_path}")

# 4. Ghi training report
avg_fold = lambda results, key: round(float(np.mean([r[key] for r in results])), 6)
std_fold = lambda results, key: round(float(np.std([r[key] for r in results])), 6)

report = {
    "model_type": "Hybrid Ensemble: XGBoost + Deep Neural Network (GPU)",
    "architecture": {
        "xgboost": "XGBClassifier (multi:softprob, GPU hist)",
        "dnn": "NIDSDeepNet (77→512→ResBlock×4→256→128→4, ~1.5M params)",
        "ensemble": f"Weighted Average (XGB={ENSEMBLE_W_XGB}, DNN={ENSEMBLE_W_DNN})",
    },
    "target_classes": list(le.classes_),
    "n_classes": int(NUM_CLASSES),
    "dataset": {
        "sources": ["CICIDS2017 (Kaggle)", "CSE-CIC-IDS2018 (Kaggle)"],
        "total_samples": len(df_bal),
        "samples_per_class": {
            cls: int((df_bal["Label_Category"] == cls).sum())
            for cls in TARGET_CLASSES
        },
        "n_features": len(avail_features),
    },
    "hyperparameters": {
        "xgboost": {k: v for k, v in XGB_PARAMS.items()
                    if k not in ("early_stopping_rounds",)},
        "dnn": {
            "hidden_dim": 512,
            "n_residual_blocks": 4,
            "dropout": 0.3,
            "optimizer": "AdamW (lr=1e-3, weight_decay=1e-4)",
            "scheduler": "OneCycleLR (cosine annealing)",
            "epochs_max": 80,
            "early_stopping_patience": 15,
            "batch_size": 2048,
            "mixed_precision": True,
        },
    },
    "cv_folds": 4,
    "results": {
        "xgboost": {
            "fold_results": xgb_fold_results,
            "avg_accuracy": avg_fold(xgb_fold_results, "accuracy"),
            "std_accuracy": std_fold(xgb_fold_results, "accuracy"),
            "avg_f1_macro": avg_fold(xgb_fold_results, "f1_macro"),
            "avg_log_loss": avg_fold(xgb_fold_results, "log_loss"),
        },
        "dnn": {
            "fold_results": dnn_fold_results,
            "avg_accuracy": avg_fold(dnn_fold_results, "accuracy"),
            "std_accuracy": std_fold(dnn_fold_results, "accuracy"),
            "avg_f1_macro": avg_fold(dnn_fold_results, "f1_macro"),
            "avg_log_loss": avg_fold(dnn_fold_results, "log_loss"),
        },
        "ensemble": {
            "fold_results": ensemble_fold_results,
            "avg_accuracy": avg_fold(ensemble_fold_results, "accuracy"),
            "std_accuracy": std_fold(ensemble_fold_results, "accuracy"),
            "avg_f1_macro": avg_fold(ensemble_fold_results, "f1_macro"),
            "avg_log_loss": avg_fold(ensemble_fold_results, "log_loss"),
            "overall_metrics": {
                "accuracy": round(metrics_ens["accuracy"], 6),
                "f1_macro": round(metrics_ens["f1_macro"], 6),
                "log_loss": round(metrics_ens["log_loss"], 6),
                "brier_score": round(metrics_ens["brier_score"], 6),
                "high_conf_pct": round(metrics_ens["high_conf_pct"], 2),
                "high_conf_accuracy": round(metrics_ens["high_conf_acc"], 6),
            },
        },
    },
    "confidence_threshold": 0.85,
    "saved_files": [
        "model_nids_multiclass.json (XGBoost)",
        "model_nids_dnn.pt (PyTorch DNN)",
        "label_encoder_multiclass.pkl",
        "standard_scaler.pkl",
        "feature_importance_nids.csv",
        "training_charts.png",
        "model_comparison.png",
    ]
}

report_path = os.path.join(OUTPUT_DIR, "training_report.json")
with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, ensure_ascii=False, indent=2)
print(f"✅ Đã lưu training report → {report_path}")

print("\n" + "=" * 70)
print("TỔNG KẾT")
print("=" * 70)
print(f"  {'Model':<12s} | {'Accuracy':>10s} | {'F1-Macro':>10s} | {'Log-Loss':>10s}")
print(f"  {'-'*50}")
print(f"  {'XGBoost':<12s} | {metrics_xgb['accuracy']:>9.4f}% | {metrics_xgb['f1_macro']:>10.4f} | {metrics_xgb['log_loss']:>10.4f}")
print(f"  {'DNN':<12s} | {metrics_dnn['accuracy']:>9.4f}% | {metrics_dnn['f1_macro']:>10.4f} | {metrics_dnn['log_loss']:>10.4f}")
print(f"  {'Ensemble':<12s} | {metrics_ens['accuracy']:>9.4f}% | {metrics_ens['f1_macro']:>10.4f} | {metrics_ens['log_loss']:>10.4f}")
print("=" * 70)
print("\n📦 Tải về các file sau từ /kaggle/working:")
print("  1. model_nids_multiclass.json  (XGBoost)")
print("  2. model_nids_dnn.pt           (PyTorch DNN)")
print("  3. label_encoder_multiclass.pkl")
print("  4. standard_scaler.pkl")
print("  5. feature_importance_nids.csv")
print("  6. training_report.json")
print("  7. training_charts.png")
print("  8. model_comparison.png")


# %%
# ============================================================================
# CELL 13 — (TÙY CHỌN) Kiểm tra nhanh Ensemble prediction
# ============================================================================
print("Kiểm tra nhanh Ensemble prediction trên 5 mẫu ngẫu nhiên...\n")

sample_idx = np.random.choice(len(X_raw), size=5, replace=False)
X_sample_raw = X_raw[sample_idx]
X_sample_sc  = X_scaled[sample_idx]
y_sample     = y[sample_idx]

# XGBoost predict
xgb_probs_sample = best_xgb_model.predict_proba(X_sample_raw)

# DNN predict
best_dnn_model.eval()
with torch.no_grad():
    X_tensor = torch.FloatTensor(X_sample_sc).to(DEVICE)
    dnn_probs_sample = torch.softmax(best_dnn_model(X_tensor), dim=-1).cpu().numpy()

# Ensemble
ens_probs_sample = ENSEMBLE_W_XGB * xgb_probs_sample + ENSEMBLE_W_DNN * dnn_probs_sample
ens_preds_sample = np.argmax(ens_probs_sample, axis=1)

print(f"  {'Idx':>3s} | {'Nhãn thực':<12s} | {'XGBoost':<12s} | {'DNN':<12s} | {'Ensemble':<12s} | {'Tự tin (%)':>10s} | {'Đúng?':<6s}")
print("  " + "-" * 85)
for i in range(5):
    true_lbl = le.inverse_transform([y_sample[i]])[0]
    xgb_lbl  = le.inverse_transform([np.argmax(xgb_probs_sample[i])])[0]
    dnn_lbl  = le.inverse_transform([np.argmax(dnn_probs_sample[i])])[0]
    ens_lbl  = le.inverse_transform([ens_preds_sample[i]])[0]
    conf     = ens_probs_sample[i].max() * 100
    correct  = "✅" if y_sample[i] == ens_preds_sample[i] else "❌"
    print(f"  {i+1:3d} | {true_lbl:<12s} | {xgb_lbl:<12s} | {dnn_lbl:<12s} | {ens_lbl:<12s} | {conf:9.2f}% | {correct}")

print("\n✅ Kiểm tra xong! Hybrid Ensemble sẵn sàng để deploy.")
