"""
=============================================================================
HƯỚNG DẪN SỬ DỤNG FILE NÀY TRÊN KAGGLE
=============================================================================
1. Vào Kaggle → "New Notebook" → chọn "Python".
2. Vào Settings → chọn Accelerator = "GPU T4 x2" (hoặc GPU P100).
3. Copy từng ô code bên dưới (từ # %% đến # %% tiếp theo) vào từng Cell.
4. Chạy tuần tự từ trên xuống dưới.
5. Ở CELL 2: Nhớ upload file "merged_cicids_network_flow.parquet"
   lên Kaggle Dataset, rồi chỉnh lại đường dẫn DATA_PATH cho đúng.
=============================================================================

FILE NÀY ĐƯỢC CHIA THÀNH 10 CELL, MỖI CELL CÁCH NHAU BẰNG DẤU  # %%
Ký hiệu  # %%  = bắt đầu một cell mới trong Kaggle Notebook.
=============================================================================
"""

# %%
# ============================================================================
# CELL 1 — Cài đặt thêm thư viện (chạy 1 lần, có thể bỏ qua nếu Kaggle
#           đã có sẵn tất cả)
# ============================================================================
import subprocess, sys

def pip_install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])

pip_install("xgboost")
pip_install("scikit-learn")
pip_install("matplotlib")
pip_install("seaborn")

print("✅ Đã cài đặt xong thư viện.")


# %%
# ============================================================================
# CELL 2 — Import thư viện & cấu hình toàn cục
# ============================================================================
import os, json, pickle, warnings
# pyrefly: ignore [missing-import]
import numpy as np
import pandas as pd
# pyrefly: ignore [missing-import]
import matplotlib.pyplot as plt
import seaborn as sns

# pyrefly: ignore [missing-import]
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    accuracy_score, f1_score, log_loss,
    confusion_matrix, classification_report
)

warnings.filterwarnings("ignore")

# ── Hạt giống ngẫu nhiên — để kết quả có thể tái tạo ───────────────────────
SEED = 42
np.random.seed(SEED)

# ── Đường dẫn dữ liệu ───────────────────────────────────────────────────────
# Tự động dò tìm file parquet trong /kaggle/input (tránh lỗi sai tên dataset)
import glob
parquet_matches = glob.glob("/kaggle/input/**/merged_cicids_network_flow.parquet", recursive=True)
if parquet_matches:
    DATA_PATH = parquet_matches[0]
    print(f"Đã tìm thấy dữ liệu tại: {DATA_PATH}")
else:
    # Dự phòng đường dẫn mặc định nếu chạy ngoài Kaggle
    DATA_PATH = "data/processed/merged_cicids_network_flow.parquet"
    print(f"Chưa tìm thấy trong /kaggle/input, fallback: {DATA_PATH}")

# ── Thư mục xuất mô hình ────────────────────────────────────────────────────
OUTPUT_DIR = "/kaggle/working"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── 4 lớp tấn công tập trung ────────────────────────────────────────────────
TARGET_CLASSES = ["Benign", "DoS", "DDoS", "PortScan"]

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

print("Cấu hình xong. Số đặc trưng:", len(FEATURE_COLS))
print("4 lớp phân loại:", TARGET_CLASSES)
print("XGBoost version:", xgb.__version__)


# %%
# ============================================================================
# CELL 3 — Đọc dữ liệu, lọc 4 lớp, lấy mẫu cân bằng
# ============================================================================

# Đọc toàn bộ file parquet
print("Đang đọc dữ liệu...")
df_raw = pd.read_parquet(DATA_PATH)
print(f"Tổng số dòng ban đầu: {len(df_raw):,}")
print("Phân bố nhãn gốc:")
print(df_raw["Label_Category"].value_counts().to_string())

# ── Lọc chỉ giữ 4 lớp mục tiêu ─────────────────────────────────────────────
df = df_raw[df_raw["Label_Category"].isin(TARGET_CLASSES)].copy()
df = df.reset_index(drop=True)

print(f"\n   Sau khi lọc 4 lớp: {len(df):,} dòng")
dist_raw = df["Label_Category"].value_counts()
print(dist_raw.to_string())

# ── Chiến lược lấy mẫu "tối đa nhưng vẫn cân bằng" ─────────────────────────
# Lý do: Không dùng cân bằng tuyệt đối (25k x 4) vì bỏ phí dữ liệu.
# Thay vào đó, lấy TOÀN BỘ PortScan và DDoS (lớp nhỏ nhất),
# và lấy mẫu Benign & DoS tối đa ~40 000 mỗi lớp.
# → Tổng ≈ 25 000 + 28 669 + 38 034 + 40 000 ≈ 131 000 – 170 000
#   Mức chênh lệch này được bù bằng scale_pos_weight trong XGBoost.
MAX_BENIGN  = 40_000
MAX_DOS     = 40_000
MAX_DDOS    = 28_669   # lấy hết
MAX_PORTSCAN = 25_000  # lấy hết

per_class_limits = {
    "Benign":   MAX_BENIGN,
    "DoS":      MAX_DOS,
    "DDoS":     MAX_DDOS,
    "PortScan": MAX_PORTSCAN,
}

sampled_frames = []
for cls, limit in per_class_limits.items():
    cls_df = df[df["Label_Category"] == cls]
    take   = min(len(cls_df), limit)
    sampled_frames.append(cls_df.sample(n=take, random_state=SEED))
    print(f"   {cls:12s}: lấy {take:,} / {len(cls_df):,} mẫu")

df_bal = pd.concat(sampled_frames, ignore_index=True)
df_bal = df_bal.sample(frac=1, random_state=SEED).reset_index(drop=True)  # shuffle

print(f"\n✅ Tổng mẫu sau lấy mẫu: {len(df_bal):,}")
print("   Phân bố cuối:")
print(df_bal["Label_Category"].value_counts().to_string())


# %%
# ============================================================================
# CELL 4 — Chuẩn bị ma trận đặc trưng X và nhãn y, encode labels
# ============================================================================

# Lấy các cột đặc trưng có trong dữ liệu
avail_features = [c for c in FEATURE_COLS if c in df_bal.columns]
missing = [c for c in FEATURE_COLS if c not in df_bal.columns]
if missing:
    print(f"⚠️ Các cột sau không có trong dataset (sẽ bỏ qua): {missing}")

X = df_bal[avail_features].values.astype(np.float32)
print(f"✅ X shape: {X.shape}")

# Encode nhãn thành số nguyên 0-3
le = LabelEncoder()
le.fit(TARGET_CLASSES)
y = le.transform(df_bal["Label_Category"])

print("   Mapping nhãn:")
for i, cls in enumerate(le.classes_):
    count = int((y == i).sum())
    print(f"   {i} → {cls:12s}: {count:,} mẫu")

# Lưu label encoder ngay để dùng ở bước sau
le_path = os.path.join(OUTPUT_DIR, "label_encoder_multiclass.pkl")
with open(le_path, "wb") as f:
    pickle.dump(le, f)
print(f"\n✅ Đã lưu label encoder → {le_path}")


# %%
# ============================================================================
# CELL 5 — Tính sample weights (cân bằng lớp nhỏ vs lớp lớn)
# ============================================================================
# Dùng sample_weight thay cho cân bằng cứng để giữ nhiều dữ liệu hơn.
# Công thức: weight_i = N / (n_classes × count_i)
# → Lớp ít mẫu được "nhân hệ số" lên, lớp nhiều mẫu bị "giảm".
# Điều này giúp mô hình không bị thiên kiến về lớp chiếm đa số.

from sklearn.utils.class_weight import compute_sample_weight

sample_weights = compute_sample_weight(class_weight="balanced", y=y)
print("✅ Sample weights đã tính:")
for i, cls in enumerate(le.classes_):
    avg_w = sample_weights[y == i].mean()
    print(f"   {cls:12s} → avg weight = {avg_w:.4f}")


# %%
# ============================================================================
# CELL 6 — Stratified 4-Fold Cross Validation với XGBoost GPU
# ============================================================================
# Các tham số chống học vẹt:
#   max_depth=6         → Cây không quá sâu, không nhớ chi tiết từng dòng
#   subsample=0.8       → Mỗi cây chỉ thấy 80% dữ liệu ngẫu nhiên
#   colsample_bytree=0.8→ Mỗi cây chỉ thấy 80% đặc trưng ngẫu nhiên
#   reg_alpha=0.1       → L1 regularization
#   reg_lambda=1.0      → L2 regularization
#   early_stopping=20   → Dừng nếu 20 vòng không cải thiện loss trên val
#   tree_method=gpu_hist→ Sử dụng GPU để huấn luyện nhanh

skf = StratifiedKFold(n_splits=4, shuffle=True, random_state=SEED)

fold_results = []
best_model   = None
best_val_f1  = -1.0
all_y_true   = []
all_y_pred   = []
all_y_prob   = []

XGB_PARAMS = dict(
    objective         = "multi:softprob",
    num_class         = len(le.classes_),
    eval_metric       = ["mlogloss", "merror"],
    tree_method       = "hist",            # Chuẩn XGBoost 2.0+ (kết hợp với device='cuda' để chạy GPU)
    device            = "cuda",
    n_estimators      = 1500,              # nhiều cây, để early stopping cắt bớt
    learning_rate     = 0.05,             # học chậm nhưng chắc
    max_depth         = 6,
    subsample         = 0.8,
    colsample_bytree  = 0.8,
    reg_alpha         = 0.1,              # L1
    reg_lambda        = 1.0,              # L2
    min_child_weight  = 5,               # tránh phân nhánh ở nút quá ít mẫu
    gamma             = 0.1,             # chỉ tách nhánh khi gain > 0.1
    random_state      = SEED,
    n_jobs            = -1,
    verbosity         = 0,
    early_stopping_rounds = 20,
)

print("🚀 Bắt đầu 4-Fold Cross Validation...\n")

for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, y), start=1):
    X_tr, X_val = X[train_idx], X[val_idx]
    y_tr, y_val = y[train_idx], y[val_idx]
    sw_tr       = sample_weights[train_idx]

    model = xgb.XGBClassifier(**XGB_PARAMS)
    model.fit(
        X_tr, y_tr,
        sample_weight     = sw_tr,
        eval_set          = [(X_val, y_val)],
        verbose           = False,
    )

    # Dự đoán
    y_pred_proba = model.predict_proba(X_val)          # shape (n, 4)
    y_pred       = np.argmax(y_pred_proba, axis=1)
    max_conf     = y_pred_proba.max(axis=1)            # độ tự tin cao nhất

    # Chỉ số đánh giá
    acc      = accuracy_score(y_val, y_pred)
    f1_macro = f1_score(y_val, y_pred, average="macro")
    logloss  = log_loss(y_val, y_pred_proba)
    best_it  = model.best_iteration

    # Phân tích độ tự tin
    high_conf_mask = max_conf >= 0.85
    high_conf_acc  = accuracy_score(y_val[high_conf_mask], y_pred[high_conf_mask]) \
                     if high_conf_mask.sum() > 0 else float("nan")
    high_conf_pct  = high_conf_mask.mean() * 100

    result = {
        "fold":           fold_idx,
        "accuracy":       round(acc,      6),
        "f1_macro":       round(f1_macro, 6),
        "log_loss":       round(logloss,  6),
        "best_iteration": best_it,
        "high_conf_pct":  round(high_conf_pct, 2),
        "high_conf_acc":  round(high_conf_acc, 6),
    }
    fold_results.append(result)

    print(f"  Fold {fold_idx}/4  |  Acc={acc:.4f}  F1={f1_macro:.4f}  "
          f"LogLoss={logloss:.4f}  BestIter={best_it}  "
          f"HighConf≥85%={high_conf_pct:.1f}% (acc={high_conf_acc:.4f})")

    # Giữ lại model tốt nhất
    if f1_macro > best_val_f1:
        best_val_f1 = f1_macro
        best_model  = model

    # Tích lũy để vẽ confusion matrix tổng hợp
    all_y_true.extend(y_val.tolist())
    all_y_pred.extend(y_pred.tolist())
    all_y_prob.extend(y_pred_proba.tolist())

print("\n✅ Cross Validation hoàn thành!")


# %%
# ============================================================================
# CELL 7 — Tổng hợp chỉ số đánh giá & in báo cáo
# ============================================================================

all_y_true = np.array(all_y_true)
all_y_pred = np.array(all_y_pred)
all_y_prob = np.array(all_y_prob)

# Chỉ số trung bình qua 4 folds
avg_acc      = np.mean([r["accuracy"]   for r in fold_results])
avg_f1       = np.mean([r["f1_macro"]   for r in fold_results])
avg_logloss  = np.mean([r["log_loss"]   for r in fold_results])
std_acc      = np.std( [r["accuracy"]   for r in fold_results])
std_f1       = np.std( [r["f1_macro"]   for r in fold_results])

# Brier Score (đo độ hiệu chỉnh xác suất)
from sklearn.metrics import brier_score_loss
from sklearn.preprocessing import label_binarize

y_true_bin = label_binarize(all_y_true, classes=list(range(len(le.classes_))))
brier_per_class = [
    brier_score_loss(y_true_bin[:, i], all_y_prob[:, i])
    for i in range(len(le.classes_))
]
avg_brier = np.mean(brier_per_class)

print("=" * 65)
print("       KẾT QUẢ TỔNG HỢP (Trung bình 4-Fold CV)")
print("=" * 65)
print(f"  Accuracy (mean ± std) : {avg_acc:.4f} ± {std_acc:.4f}")
print(f"  F1-Macro (mean ± std) : {avg_f1:.4f}  ± {std_f1:.4f}")
print(f"  Log-Loss (mean)       : {avg_logloss:.4f}")
print(f"  Brier Score (mean)    : {avg_brier:.4f}  (↓ càng nhỏ càng tốt)")
print("=" * 65)

# Báo cáo per-class
print("\n📊 Báo cáo phân loại chi tiết (toàn bộ dữ liệu validation):")
print(classification_report(
    all_y_true, all_y_pred,
    target_names=le.classes_,
    digits=4
))

# Phân tích độ tự tin tổng thể
max_conf_all   = all_y_prob.max(axis=1)
high_conf_mask = max_conf_all >= 0.85
print(f"Dự đoán với độ tự tin ≥ 85%: {high_conf_mask.mean()*100:.1f}% tổng số mẫu")
print(f"Accuracy trong nhóm ≥ 85% tự tin: "
      f"{accuracy_score(all_y_true[high_conf_mask], all_y_pred[high_conf_mask]):.4f}")
print(f"Accuracy trong nhóm < 85% tự tin : "
      f"{accuracy_score(all_y_true[~high_conf_mask], all_y_pred[~high_conf_mask]):.4f}")


# %%
# ============================================================================
# CELL 8 — Vẽ biểu đồ: Confusion Matrix & Feature Importance (Top-15)
# ============================================================================
fig, axes = plt.subplots(1, 2, figsize=(18, 7))

# ── Confusion Matrix ─────────────────────────────────────────────────────────
cm = confusion_matrix(all_y_true, all_y_pred)
cm_pct = cm.astype(float) / cm.sum(axis=1, keepdims=True) * 100

sns.heatmap(
    cm_pct, annot=True, fmt=".1f", cmap="Blues",
    xticklabels=le.classes_, yticklabels=le.classes_,
    linewidths=0.5, linecolor="gray",
    ax=axes[0]
)
axes[0].set_title("Confusion Matrix (%) — 4-Fold CV\n"
                  f"Accuracy={avg_acc:.4f}  F1-Macro={avg_f1:.4f}", fontsize=13)
axes[0].set_xlabel("Nhãn dự đoán", fontsize=11)
axes[0].set_ylabel("Nhãn thực tế", fontsize=11)

# ── Feature Importance (Top-15) ──────────────────────────────────────────────
fi_scores = best_model.get_booster().get_score(importance_type="gain")
fi_df = (
    pd.DataFrame.from_dict(fi_scores, orient="index", columns=["gain"])
    .sort_values("gain", ascending=False)
    .head(15)
)

# Ánh xạ tên cột (f0, f1, ...) về tên thật
col_map = {f"f{i}": c for i, c in enumerate(avail_features)}
fi_df.index = [col_map.get(k, k) for k in fi_df.index]

fi_df.plot(kind="barh", ax=axes[1], color="steelblue", legend=False)
axes[1].invert_yaxis()
axes[1].set_title("Top-15 Feature Importance (Gain)\nMô hình tốt nhất qua 4-Fold", fontsize=13)
axes[1].set_xlabel("Gain (đóng góp trung bình vào quyết định)", fontsize=11)
axes[1].set_ylabel("")
for bar in axes[1].patches:
    axes[1].text(
        bar.get_width() * 1.01, bar.get_y() + bar.get_height() / 2,
        f"{bar.get_width():.0f}", va="center", fontsize=8
    )

plt.tight_layout()
plot_path = os.path.join(OUTPUT_DIR, "training_charts.png")
plt.savefig(plot_path, dpi=150, bbox_inches="tight")
plt.show()
print(f"✅ Đã lưu biểu đồ → {plot_path}")


# %%
# ============================================================================
# CELL 9 — Lưu mô hình tốt nhất & training_report.json
# ============================================================================

# Lưu XGBoost model
model_path = os.path.join(OUTPUT_DIR, "model_nids_multiclass.json")
best_model.save_model(model_path)
print(f"Đã lưu mô hình → {model_path}")

# Lưu feature importance CSV
fi_full = (
    pd.DataFrame.from_dict(
        best_model.get_booster().get_score(importance_type="gain"),
        orient="index", columns=["gain"]
    )
    .sort_values("gain", ascending=False)
)
fi_full.index = [col_map.get(k, k) for k in fi_full.index]
fi_csv_path = os.path.join(OUTPUT_DIR, "feature_importance_nids.csv")
fi_full.to_csv(fi_csv_path)
print(f"Đã lưu feature importance → {fi_csv_path}")

# Ghi training report
report = {
    "model_type": "XGBoost Multiclass (GPU)",
    "target_classes": list(le.classes_),
    "n_classes": int(len(le.classes_)),
    "dataset": {
        "total_samples": len(df_bal),
        "samples_per_class": {
            cls: int((df_bal["Label_Category"] == cls).sum())
            for cls in TARGET_CLASSES
        }
    },
    "hyperparameters": {k: v for k, v in XGB_PARAMS.items()
                        if k not in ("early_stopping_rounds",)},
    "cv_folds": 4,
    "fold_results": fold_results,
    "avg_accuracy": round(float(avg_acc),     6),
    "std_accuracy": round(float(std_acc),     6),
    "avg_f1_macro": round(float(avg_f1),      6),
    "std_f1_macro": round(float(std_f1),      6),
    "avg_log_loss": round(float(avg_logloss), 6),
    "avg_brier_score": round(float(avg_brier), 6),
    "confidence": {
        "threshold": 0.85,
        "high_conf_pct": round(float(high_conf_mask.mean() * 100), 2),
        "high_conf_accuracy": round(
            float(accuracy_score(all_y_true[high_conf_mask], all_y_pred[high_conf_mask])), 6
        ),
    },
    "saved_files": [
        "model_nids_multiclass.json",
        "label_encoder_multiclass.pkl",
        "feature_importance_nids.csv",
        "training_charts.png",
    ]
}

report_path = os.path.join(OUTPUT_DIR, "training_report.json")
with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, ensure_ascii=False, indent=2)
print(f"Đã lưu training report → {report_path}")

print("\n" + "=" * 65)
print("TỔNG KẾT")
print("=" * 65)
print(f"Accuracy trung bình : {avg_acc*100:.2f}%  (±{std_acc*100:.2f}%)")
print(f"F1-Macro trung bình : {avg_f1:.4f}        (±{std_f1:.4f})")
print(f"Log-Loss trung bình : {avg_logloss:.4f}")
print(f"Brier Score         : {avg_brier:.4f}")
print(f"Dự đoán tự tin ≥85% : {high_conf_mask.mean()*100:.1f}%")
print("=" * 65)
print("\nHoàn thành huấn luyện! Tải về 4 file sau từ /kaggle/working:")
print("1. model_nids_multiclass.json")
print("2. label_encoder_multiclass.pkl")
print("3. feature_importance_nids.csv")
print("4. training_report.json")
print("5. training_charts.png  (biểu đồ đánh giá)")


# %%
# ============================================================================
# CELL 10 — (TÙY CHỌN) Kiểm tra nhanh độ tự tin với mẫu giả lập
# ============================================================================
print("Kiểm tra nhanh dự đoán trên 5 mẫu ngẫu nhiên từ tập val cuối...")

# Lấy 5 mẫu ngẫu nhiên từ X và y
sample_idx = np.random.choice(len(X), size=5, replace=False)
X_sample = X[sample_idx]
y_sample = y[sample_idx]

probs = best_model.predict_proba(X_sample)
preds = np.argmax(probs, axis=1)

print("\n  Idx | Nhãn thực    | Nhãn dự đoán | Tự tin (%) | Đúng?  | Mức tự tin")
print("  " + "-" * 75)
for i in range(5):
    true_lbl  = le.inverse_transform([y_sample[i]])[0]
    pred_lbl  = le.inverse_transform([preds[i]])[0]
    confidence = probs[i].max() * 100
    correct   = "✅" if y_sample[i] == preds[i] else "❌"
    level     = "🔴 Rất tự tin" if confidence >= 85 else "🟡 Không chắc"
    print(f"  {i+1:3d} | {true_lbl:12s} | {pred_lbl:12s} | {confidence:9.2f}% | {correct}     | {level}")

print("\n✅ Kiểm tra xong!")
