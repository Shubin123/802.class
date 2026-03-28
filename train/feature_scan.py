import pandas as pd
import numpy as np
import torch
import torch.nn as nn

KEEP_FEATURES = ['iat', 'frame_len', 'fc_type', 'fc_subtype', 'duration',
                 'signal_dbm', 'data_rate', 'mcs_index']

df = pd.read_parquet("../data/dataset_output/dataset.parquet")
feature_cols = [c for c in KEEP_FEATURES if c in df.columns]
df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=['label'] + feature_cols)

print("=== Raw feature stats ===")
for c in feature_cols:
    col = df[c]
    print(f"  {c:15s}  min={col.min():.4f}  max={col.max():.4f}  std={col.std():.6f}  nunique={col.nunique()}")

print("\n=== Constant features per label (BatchNorm killer) ===")
per_label_std = df.groupby('label')[feature_cols].std()
zero_std = (per_label_std == 0).sum()
print(zero_std)

print("\n=== Tensor check after z-score ===")
feats = df[feature_cols].values.astype(np.float32)
mean, std = feats.mean(0), feats.std(0) + 1e-8
feats = np.clip((feats - mean) / std, -10, 10)
t = torch.from_numpy(feats[:128]).float().unsqueeze(0).transpose(1, 2)
print(f"  isnan: {torch.isnan(t).any().item()}")
print(f"  isinf: {torch.isinf(t).any().item()}")

class Simple1DCNN(nn.Module):
    def __init__(self, num_classes=120, in_channels=8):
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv1d(in_channels, 64,  kernel_size=3, padding=1), nn.BatchNorm1d(64),  nn.ReLU(), nn.MaxPool1d(2),
            nn.Conv1d(64,  128, kernel_size=3, padding=1), nn.BatchNorm1d(128), nn.ReLU(), nn.MaxPool1d(2),
            nn.Conv1d(128, 256, kernel_size=3, padding=1), nn.BatchNorm1d(256), nn.ReLU(), nn.AdaptiveAvgPool1d(1),
            nn.Flatten(), nn.Dropout(0.3), nn.Linear(256, 120)
        )
    def forward(self, x):
        return self.net(x)

model = Simple1DCNN()
with torch.no_grad():
    out = model(t)
print(f"  output isnan: {torch.isnan(out).any().item()}")
print(f"  output sample: {out[0,:5]}")