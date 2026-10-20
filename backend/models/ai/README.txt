=== HƯỚNG DẪN CẬP NHẬT MODEL AI ===

Thư mục này chứa model AI NIDS 4 lớp (Benign, DDoS, DoS, PortScan)
đã huấn luyện bằng XGBoost trên Kaggle GPU.

Các file cần thiết (copy từ output Kaggle):
1. model_nids_multiclass.json  - Model XGBoost 4 lớp (~2MB)
2. label_encoder_multiclass.pkl - Bộ mã hóa nhãn 4 lớp
3. training_report.json        - Báo cáo kết quả huấn luyện
4. training_charts.png         - Biểu đồ huấn luyện
5. feature_importance_nids.csv - Bảng xếp hạng đặc trưng (tùy chọn)

LƯU Ý QUAN TRỌNG:
- KHÔNG copy model từ archive/old_dataset_models/ hoặc archive/old_models/
  vì đó là model CŨ 9 lớp (~9.6MB), hoàn toàn khác model hiện tại.
- Model hiện tại: 4 lớp, 928 cây, ~2MB
- Model cũ: 9 lớp, 2700 cây, ~9.6MB

Script huấn luyện: nids_train_cells.py (chạy trên Kaggle)
Dataset: dataset/processed/merged_cicids_network_flow.parquet
