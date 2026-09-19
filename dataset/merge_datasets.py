"""
=============================================================================
merge_datasets.py
-----------------------------------------------------------------------------
Chuẩn hoá và gộp các tập dữ liệu an toàn mạng trong thư mục dataset/:
1. Network Flow NIDS Dataset (CICFlowMeter 78-feature standard):
   - Clean_CICIDS2017.csv
   - 02-14-2018.csv.zip (CSE-CIC-IDS2018: FTP & SSH Brute Force)
   - Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet.zip (Botnet)
   - DNS-testing.parquet (DrDoS_DNS)

2. Web Application Security Dataset (NLP / WAF Payloads):
   - HttpParamsDataset-master.zip (HTTP requests & attacks)
   - SQLiV3.csv.zip (SQL Injection sentences)

Đầu ra được lưu tại dataset/processed/:
- merged_cicids_network_flow.parquet & .csv
- merged_web_payload.parquet & .csv
- dataset_summary.json
=============================================================================
"""

import os
import io
import sys
import json
import zipfile
import argparse
# pyrefly: ignore [missing-import]
import numpy as np
import pandas as pd

# Thiết lập UTF-8 cho console Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Thư mục gốc dataset và thư mục xuất kết quả
DATASET_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(DATASET_DIR, "processed")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Danh sách 77 đặc trưng luồng mạng chuẩn CICFlowMeter (ngoài Protocol và Label)
STANDARD_FLOW_FEATURES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Fwd Packets Length Total', 'Bwd Packets Length Total',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s',
    'Packet Length Min', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Avg Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init Fwd Win Bytes', 'Init Bwd Win Bytes',
    'Fwd Act Data Packets', 'Fwd Seg Size Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

ALL_FEATURE_COLS = ['Protocol'] + STANDARD_FLOW_FEATURES

# Bản đồ phân loại nhãn tấn công cấp cao (Label_Category)
LABEL_CATEGORY_MAP = {
    'BENIGN': 'Benign',
    'Benign': 'Benign',
    # DoS
    'DoS_Hulk': 'DoS',
    'DoS_GoldenEye': 'DoS',
    'DoS_slowloris': 'DoS',
    'DoS_Slowhttptest': 'DoS',
    # DDoS
    'DDoS': 'DDoS',
    'DrDoS_DNS': 'DDoS',
    # Brute Force
    'FTP-BruteForce': 'BruteForce',
    'SSH-Bruteforce': 'BruteForce',
    'FTPPatator': 'BruteForce',
    'SSHPatator': 'BruteForce',
    'Web_Attack_Brute_Force': 'BruteForce',
    # Botnet
    'Bot': 'Botnet',
    # Scanning
    'PortScan': 'PortScan',
    # Web Attacks
    'Web_Attack_XSS': 'Web_Attack',
    'Web_Attack_Sql_Injection': 'Web_Attack',
    # Infiltration / Heartbleed
    'Infiltration': 'Infiltration',
    'Heartbleed': 'Heartbleed'
}

# Ánh xạ tên cột từ CICIDS2017 sang chuẩn
MAP_CICIDS2017 = {
    'Total Length of Fwd Packets': 'Fwd Packets Length Total',
    'Total Length of Bwd Packets': 'Bwd Packets Length Total',
    'Min Packet Length': 'Packet Length Min',
    'Max Packet Length': 'Packet Length Max',
    'Average Packet Size': 'Avg Packet Size',
    'Init_Win_bytes_forward': 'Init Fwd Win Bytes',
    'Init_Win_bytes_backward': 'Init Bwd Win Bytes',
    'act_data_pkt_fwd': 'Fwd Act Data Packets',
    'min_seg_size_forward': 'Fwd Seg Size Min',
}

# Ánh xạ tên cột từ 02-14-2018 (CSE-CIC-IDS2018) sang chuẩn
MAP_CICIDS2018 = {
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
}

def clean_and_cast_df(df: pd.DataFrame) -> pd.DataFrame:
    """Làm sạch các giá trị vô hạn, NaN và tối ưu kiểu dữ liệu float32/int32."""
    for col in df.columns:
        if col in ('Label_Subtype', 'Label_Category', 'Is_Attack'):
            continue
        # Chuyển đổi sang số nếu đang là object/str
        if df[col].dtype == object or str(df[col].dtype) == 'category':
            df[col] = pd.to_numeric(df[col], errors='coerce')
        
        # Thay thế inf và -inf bằng NaN rồi fillna 0.0
        df[col] = df[col].replace([np.inf, -np.inf], np.nan).fillna(0.0)
        
        # Downcast để tiết kiệm RAM
        if col == 'Protocol':
            df[col] = df[col].astype(np.int32)
        else:
            df[col] = df[col].astype(np.float32)
            
    return df


def load_clean_cicids2017(csv_path: str, max_samples_per_label: int = 25000) -> pd.DataFrame:
    """Đọc Clean_CICIDS2017.csv theo chunk và lấy mẫu cân bằng."""
    print(f"[1/4] Đang xử lý Clean_CICIDS2017.csv...")
    if not os.path.exists(csv_path):
        print(f"  [!] Không tìm thấy tệp {csv_path}")
        return pd.DataFrame()

    chunks = []
    counts_by_label = {}
    chunk_size = 100000

    for chunk in pd.read_csv(csv_path, chunksize=chunk_size, low_memory=False):
        # Chuẩn hoá tên cột
        chunk.columns = [c.strip() for c in chunk.columns]
        chunk = chunk.rename(columns=MAP_CICIDS2017)
        
        # Tạo Protocol từ Destination Port nếu thiếu
        if 'Protocol' not in chunk.columns:
            if 'Destination Port' in chunk.columns:
                # Cổng 53 thường là UDP (17), các dịch vụ web/ssh/ftp thường là TCP (6)
                chunk['Protocol'] = np.where(chunk['Destination Port'] == 53, 17, 6)
            else:
                chunk['Protocol'] = 6
                
        # Giữ lại các cột chuẩn + Label
        cols_to_keep = [c for c in ALL_FEATURE_COLS if c in chunk.columns] + ['Label']
        chunk = chunk[cols_to_keep]

        # Lấy mẫu cân bằng
        for label, group in chunk.groupby('Label'):
            current_count = counts_by_label.get(label, 0)
            if current_count >= max_samples_per_label:
                continue
            needed = max_samples_per_label - current_count
            sampled_group = group.head(needed)
            chunks.append(sampled_group)
            counts_by_label[label] = current_count + len(sampled_group)

    df_2017 = pd.concat(chunks, ignore_index=True)
    df_2017['Label_Subtype'] = df_2017['Label'].str.strip()
    df_2017 = df_2017.drop(columns=['Label'], errors='ignore')
    print(f"  -> Hoàn thành CICIDS2017: {len(df_2017):,} dòng. Phân bố nhãn:")
    for k, v in counts_by_label.items():
        print(f"     - {k}: {v:,}")
    return df_2017


def load_02_14_2018(zip_path: str, max_samples_per_label: int = 25000) -> pd.DataFrame:
    """Đọc 02-14-2018.csv.zip (FTP & SSH Brute Force) theo chunk và lấy mẫu cân bằng."""
    print(f"[2/4] Đang xử lý 02-14-2018.csv.zip...")
    if not os.path.exists(zip_path):
        print(f"  [!] Không tìm thấy tệp {zip_path}")
        return pd.DataFrame()

    chunks = []
    counts_by_label = {}
    chunk_size = 100000

    with zipfile.ZipFile(zip_path, 'r') as z:
        csv_filename = [n for n in z.namelist() if n.endswith('.csv')][0]
        with z.open(csv_filename) as f:
            for chunk in pd.read_csv(f, chunksize=chunk_size, low_memory=False):
                chunk.columns = [c.strip() for c in chunk.columns]
                chunk = chunk.rename(columns=MAP_CICIDS2018)

                # Bỏ qua nhãn Benign nếu đã có đủ từ CICIDS2017, tập trung lấy Brute Force
                chunk['Label'] = chunk['Label'].astype(str).str.strip()
                # Lọc hàng tiêu đề lặp lại nếu có
                chunk = chunk[chunk['Label'] != 'Label']

                cols_to_keep = [c for c in ALL_FEATURE_COLS if c in chunk.columns] + ['Label']
                chunk = chunk[cols_to_keep]

                for label, group in chunk.groupby('Label'):
                    if label == 'Benign':
                        # Chỉ lấy tối đa 5000 Benign từ 2018 để đa dạng nguồn
                        allowed = min(max_samples_per_label, 5000)
                    else:
                        allowed = max_samples_per_label

                    current_count = counts_by_label.get(label, 0)
                    if current_count >= allowed:
                        continue
                    needed = allowed - current_count
                    sampled = group.head(needed)
                    chunks.append(sampled)
                    counts_by_label[label] = current_count + len(sampled)

    df_2018 = pd.concat(chunks, ignore_index=True)
    df_2018['Label_Subtype'] = df_2018['Label'].str.strip()
    df_2018 = df_2018.drop(columns=['Label'], errors='ignore')
    print(f"  -> Hoàn thành 02-14-2018: {len(df_2018):,} dòng. Phân bố nhãn:")
    for k, v in counts_by_label.items():
        print(f"     - {k}: {v:,}")
    return df_2018


def load_botnet_parquet(zip_path: str, max_samples_per_label: int = 25000) -> pd.DataFrame:
    """Đọc Botnet-Friday-02-03-2018 parquet và lấy mẫu cân bằng Botnet."""
    print(f"[3/4] Đang xử lý Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet.zip...")
    if not os.path.exists(zip_path):
        print(f"  [!] Không tìm thấy tệp {zip_path}")
        return pd.DataFrame()

    with zipfile.ZipFile(zip_path, 'r') as z:
        pq_filename = [n for n in z.namelist() if n.endswith('.parquet')][0]
        with z.open(pq_filename) as f:
            df = pd.read_parquet(f)

    df.columns = [c.strip() for c in df.columns]
    df['Label'] = df['Label'].astype(str).str.strip()

    # Lấy mẫu: 25k Bot và 5k Benign (để đa dạng Benign 2018)
    bot_samples = df[df['Label'] == 'Bot'].head(max_samples_per_label)
    benign_samples = df[df['Label'] == 'Benign'].head(5000)

    sampled_df = pd.concat([bot_samples, benign_samples], ignore_index=True)
    cols_to_keep = [c for c in ALL_FEATURE_COLS if c in sampled_df.columns] + ['Label']
    sampled_df = sampled_df[cols_to_keep]

    sampled_df['Label_Subtype'] = sampled_df['Label']
    sampled_df = sampled_df.drop(columns=['Label'], errors='ignore')
    print(f"  -> Hoàn thành Botnet: {len(sampled_df):,} dòng (Bot: {len(bot_samples):,}, Benign: {len(benign_samples):,})")
    return sampled_df


def load_dns_testing(pq_path: str) -> pd.DataFrame:
    """Đọc DNS-testing.parquet (DrDoS_DNS DDoS traffic)."""
    print(f"[4/4] Đang xử lý DNS-testing.parquet...")
    if not os.path.exists(pq_path):
        print(f"  [!] Không tìm thấy tệp {pq_path}")
        return pd.DataFrame()

    df = pd.read_parquet(pq_path)
    df.columns = [c.strip() for c in df.columns]
    df['Label'] = df['Label'].astype(str).str.strip()

    cols_to_keep = [c for c in ALL_FEATURE_COLS if c in df.columns] + ['Label']
    df = df[cols_to_keep]
    df['Label_Subtype'] = df['Label']
    df = df.drop(columns=['Label'], errors='ignore')
    print(f"  -> Hoàn thành DNS Testing: {len(df):,} dòng (DrDoS_DNS: {len(df[df['Label_Subtype']=='DrDoS_DNS']):,})")
    return df


def build_network_flow_dataset(max_samples_per_label: int = 25000):
    """Gộp toàn bộ 4 dataset Network Flow CICFlowMeter thành 1 dataset hoàn chỉnh."""
    print("=" * 70)
    print("BƯỚC 1: XÂY DỰNG DATASET LUỒNG MẠNG (CICFLOWMETER NIDS)")
    print("=" * 70)

    p1 = os.path.join(DATASET_DIR, "Clean_CICIDS2017.csv")
    p2 = os.path.join(DATASET_DIR, "02-14-2018.csv.zip")
    p3 = os.path.join(DATASET_DIR, "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet.zip")
    p4 = os.path.join(DATASET_DIR, "DNS-testing.parquet")

    df1 = load_clean_cicids2017(p1, max_samples_per_label)
    df2 = load_02_14_2018(p2, max_samples_per_label)
    df3 = load_botnet_parquet(p3, max_samples_per_label)
    df4 = load_dns_testing(p4)

    print("\nĐang hợp nhất các tập dữ liệu luồng mạng...")
    dfs = [d for d in [df1, df2, df3, df4] if not d.empty]
    merged_df = pd.concat(dfs, ignore_index=True)

    # Đảm bảo có đủ 78 thuộc tính
    for col in ALL_FEATURE_COLS:
        if col not in merged_df.columns:
            merged_df[col] = 0.0

    # Ánh xạ nhãn phân loại cấp cao (Label_Category)
    merged_df['Label_Category'] = merged_df['Label_Subtype'].map(
        lambda x: LABEL_CATEGORY_MAP.get(x, 'Attack' if x.upper() != 'BENIGN' else 'Benign')
    )

    # Tạo nhãn nhị phân Is_Attack (0: Benign, 1: Attack)
    merged_df['Is_Attack'] = np.where(merged_df['Label_Category'] == 'Benign', 0, 1).astype(np.int8)

    # Sắp xếp lại thứ tự cột
    final_cols = ALL_FEATURE_COLS + ['Label_Subtype', 'Label_Category', 'Is_Attack']
    merged_df = merged_df[final_cols]

    print("Đang làm sạch và tối ưu kiểu dữ liệu (inf, NaN, float32)...")
    merged_df = clean_and_cast_df(merged_df)

    # Shuffle dữ liệu để khi train/validation/test các nhãn phân bố đều
    merged_df = merged_df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    # Lưu Parquet (chuẩn lưu trữ nén tối ưu, đọc cực nhanh)
    pq_out = os.path.join(OUTPUT_DIR, "merged_cicids_network_flow.parquet")
    csv_out = os.path.join(OUTPUT_DIR, "merged_cicids_network_flow.csv")

    print(f"\nĐang lưu Parquet: {pq_out}...")
    merged_df.to_parquet(pq_out, index=False, compression='snappy')
    print(f"  -> Dung lượng Parquet: {os.path.getsize(pq_out)/(1024*1024):.2f} MB")

    print(f"Đang lưu CSV: {csv_out}...")
    merged_df.to_csv(csv_out, index=False)
    print(f"  -> Dung lượng CSV: {os.path.getsize(csv_out)/(1024*1024):.2f} MB")

    return merged_df


def build_web_payload_dataset():
    """Gộp các tệp chuỗi Payload Web (HttpParamsDataset + SQLiV3) thành 1 dataset WAF/NLP."""
    print("\n" + "=" * 70)
    print("BƯỚC 2: XÂY DỰNG DATASET PAYLOAD WEB (WAF / NLP)")
    print("=" * 70)

    records = []

    # 1. HttpParamsDataset
    http_zip = os.path.join(DATASET_DIR, "HttpParamsDataset-master.zip")
    if os.path.exists(http_zip):
        print("Đang xử lý HttpParamsDataset-master.zip...")
        with zipfile.ZipFile(http_zip, 'r') as z:
            with z.open("HttpParamsDataset-master/payload_full.csv") as f:
                df_http = pd.read_csv(f)
                for _, row in df_http.iterrows():
                    p = str(row['payload']) if pd.notna(row['payload']) else ""
                    atk = str(row['attack_type']).strip().lower()
                    is_atk = 0 if atk == 'norm' else 1
                    records.append({
                        'payload': p,
                        'attack_type': atk,
                        'is_attack': is_atk,
                        'source': 'HttpParamsDataset'
                    })
        print(f"  -> Nạp thành công {len(df_http):,} mẫu từ HttpParamsDataset.")

    # 2. SQLiV3
    sqli_zip = os.path.join(DATASET_DIR, "SQLiV3.csv.zip")
    if os.path.exists(sqli_zip):
        print("Đang xử lý SQLiV3.csv.zip...")
        with zipfile.ZipFile(sqli_zip, 'r') as z:
            with z.open("SQLiV3.csv") as f:
                df_sqli = pd.read_csv(f, on_bad_lines='skip')
                for _, row in df_sqli.iterrows():
                    sentence = str(row['Sentence']) if pd.notna(row.get('Sentence')) else ""
                    raw_lbl = str(row.get('Label', '')).strip()
                    if raw_lbl in ('0', '1'):
                        is_atk = int(raw_lbl)
                        atk = 'sqli' if is_atk == 1 else 'norm'
                        records.append({
                            'payload': sentence,
                            'attack_type': atk,
                            'is_attack': is_atk,
                            'source': 'SQLiV3'
                        })
        print(f"  -> Nạp thành công {len(df_sqli):,} mẫu từ SQLiV3.")

    df_web = pd.DataFrame(records)
    # Loại bỏ trùng lặp và chuỗi rỗng
    df_web = df_web[df_web['payload'].str.strip() != ""]
    df_web = df_web.drop_duplicates(subset=['payload'])
    df_web = df_web.sample(frac=1.0, random_state=42).reset_index(drop=True)

    pq_out = os.path.join(OUTPUT_DIR, "merged_web_payload.parquet")
    csv_out = os.path.join(OUTPUT_DIR, "merged_web_payload.csv")

    print(f"\nĐang lưu Parquet Web: {pq_out}...")
    df_web.to_parquet(pq_out, index=False, compression='snappy')
    print(f"Đang lưu CSV Web: {csv_out}...")
    df_web.to_csv(csv_out, index=False)
    print(f"  -> Hoàn thành Dataset Web: {len(df_web):,} dòng.")
    print("     Phân bố attack_type:")
    for atk, cnt in df_web['attack_type'].value_counts().items():
        print(f"     - {atk}: {cnt:,}")

    return df_web


def export_summary(df_net: pd.DataFrame, df_web: pd.DataFrame):
    """Xuất file tóm tắt thống kê dataset json."""
    summary = {
        "network_flow_dataset": {
            "total_samples": len(df_net),
            "feature_columns_count": len(ALL_FEATURE_COLS),
            "feature_columns": ALL_FEATURE_COLS,
            "target_columns": ['Label_Subtype', 'Label_Category', 'Is_Attack'],
            "label_category_distribution": df_net['Label_Category'].value_counts().to_dict(),
            "label_subtype_distribution": df_net['Label_Subtype'].value_counts().to_dict(),
            "is_attack_distribution": {
                "Benign (0)": int((df_net['Is_Attack'] == 0).sum()),
                "Attack (1)": int((df_net['Is_Attack'] == 1).sum())
            },
            "output_files": [
                "dataset/processed/merged_cicids_network_flow.parquet",
                "dataset/processed/merged_cicids_network_flow.csv"
            ]
        },
        "web_payload_dataset": {
            "total_samples": len(df_web),
            "columns": list(df_web.columns),
            "attack_type_distribution": df_web['attack_type'].value_counts().to_dict(),
            "is_attack_distribution": {
                "Normal (0)": int((df_web['is_attack'] == 0).sum()),
                "Attack (1)": int((df_web['is_attack'] == 1).sum())
            },
            "output_files": [
                "dataset/processed/merged_web_payload.parquet",
                "dataset/processed/merged_web_payload.csv"
            ]
        }
    }

    summary_path = os.path.join(OUTPUT_DIR, "dataset_summary.json")
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\nĐã xuất bản tóm tắt thống kê: {summary_path}")


def main():
    parser = argparse.ArgumentParser(description="Gộp và chuẩn hoá dataset NIDS và Web Payload")
    parser.add_argument("--sample_size", type=int, default=25000,
                        help="Số lượng mẫu tối đa cho mỗi lớp tấn công lớn (mặc định 25000 để cân bằng dữ liệu)")
    args = parser.parse_args()

    df_net = build_network_flow_dataset(max_samples_per_label=args.sample_size)
    df_web = build_web_payload_dataset()
    export_summary(df_net, df_web)

    print("\n" + "=" * 70)
    print("HOÀN THÀNH TẤT CẢ CÁC BƯỚC GỘP VÀ CHUẨN HOÁ DATASET!")
    print("=" * 70)

if __name__ == "__main__":
    main()
