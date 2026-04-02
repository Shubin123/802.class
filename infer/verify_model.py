#!/usr/bin/env python3
"""
Verification: Feed training parquet data directly through the model
to prove whether the model can actually distinguish classes.

If it predicts correctly → feature extraction in inference.py is the problem.
If it predicts wrong → the model itself is the problem.
"""
import sys, io, zipfile
from pathlib import Path
from collections import Counter
import numpy as np
import torch

# Import model
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "train", str(Path(__file__).parent.resolve() / ".." / "train" / "train.py"))
_train = importlib.util.module_from_spec(_spec)
sys.modules["train"] = _train
_spec.loader.exec_module(_train)
TrafficResNet = _train.TrafficResNet

SCRIPT_DIR = Path(__file__).parent.resolve()
CKPT_DIR   = SCRIPT_DIR / ".." / "train" / "checkpoints"
DATA_ZIP   = SCRIPT_DIR / ".." / "data" / "dataset_output" / "dataset.parquet.zip"

def main():
    import pandas as pd

    # ── 1. Load training parquet ──
    print("[1] Loading training parquet …")
    if DATA_ZIP.exists():
        zf = zipfile.ZipFile(DATA_ZIP)
        with zf.open(zf.namelist()[0]) as f:
            df = pd.read_parquet(io.BytesIO(f.read()))
    else:
        df = pd.read_parquet(SCRIPT_DIR / ".." / "data" / "dataset_output" / "dataset.parquet")
    print(f"    Shape: {df.shape}, Columns: {list(df.columns)}")

    # ── 2. Replicate train.py's exact feature selection ──
    exclude = {'label', 'timestamp', '_blk', '_fid'}
    feature_cols = [c for c in df.columns if c not in exclude]
    valid_cols = [c for c in feature_cols if df[c].nunique() > 1]
    print(f"    Valid features ({len(valid_cols)}): {valid_cols}")

    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=['label'] + valid_cols).reset_index(drop=True)

    # Remap labels (same as train.py)
    unique_labels = sorted(df['label'].unique())
    label_map = {orig: i for i, orig in enumerate(unique_labels)}
    df['label'] = df['label'].map(label_map)
    num_classes = len(unique_labels)
    print(f"    {len(df):,} rows, {num_classes} classes")

    # ── 3. Load model (prefer best_resnet600.pt) ──
    print("\n[2] Loading checkpoint …")
    ckpt = CKPT_DIR / "best_resnet600.pt"
    if not ckpt.exists():
        # Fallback: most recent
        for p in sorted(CKPT_DIR.glob("best_resnet*.pt"), key=lambda x: x.stat().st_mtime, reverse=True):
            ckpt = p; break
    if not ckpt.exists():
        print("No checkpoint found!"); return

    dev = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    sd = torch.load(ckpt, map_location=dev, weights_only=True)
    in_ch = sd['stem.0.weight'].shape[1]
    n_cls = sd['fc.weight'].shape[0]
    model = TrafficResNet(num_classes=n_cls, in_channels=in_ch).to(dev)
    model.load_state_dict(sd)
    model.eval()
    print(f"    {ckpt.name}: in_channels={in_ch}, classes={n_cls}")

    if in_ch != len(valid_cols):
        print(f"    WARNING: checkpoint expects {in_ch} features, parquet has {len(valid_cols)}")

    # ── 4. Compute normalization ONCE from all data ──
    ws = 128
    all_feats = df[valid_cols].values.astype(np.float32)
    all_feats = np.nan_to_num(all_feats, nan=0.0, posinf=0.0, neginf=0.0)
    total_w = len(all_feats) // ws
    all_windowed = all_feats[:total_w * ws].reshape(total_w, ws, len(valid_cols)).transpose(0, 2, 1)
    global_mean = all_windowed.mean(axis=(0, 2), keepdims=True)
    global_std  = all_windowed.std(axis=(0, 2), keepdims=True) + 1e-8
    print(f"\n    Normalization: {total_w} total windows")
    print(f"    Per-feature mean: {global_mean.squeeze()}")
    print(f"    Per-feature std:  {global_std.squeeze()}")

    # ── 5. Verify per label ──
    print(f"\n[3] Verifying predictions per label (window_size={ws}) …")
    print(f"    {'Label':>6} {'Rows':>8} {'Win':>5} {'TopPred':>8} {'Correct':>8} {'AvgConf':>8}")
    print(f"    {'-'*55}")

    total_correct = 0
    total_windows = 0

    for lbl in sorted(df['label'].unique()):
        group = df[df['label'] == lbl]
        feats = group[valid_cols].values.astype(np.float32)
        feats = np.nan_to_num(feats, nan=0.0, posinf=0.0, neginf=0.0)
        n = len(feats) // ws
        if n == 0:
            continue
        feats = feats[:n * ws].reshape(n, ws, len(valid_cols)).transpose(0, 2, 1)

        # Normalize with global stats + clip
        feats = np.clip((feats - global_mean) / global_std, -10, 10)

        with torch.no_grad():
            logits = model(torch.from_numpy(feats).float().to(dev))
            # Use log_softmax for numerical stability
            log_probs = torch.log_softmax(logits, 1)
            probs = torch.exp(log_probs).cpu().numpy()
            preds = logits.argmax(1).cpu().numpy()

        counts = Counter(preds)
        top_pred, _ = counts.most_common(1)[0]
        correct = int((preds == lbl).sum())
        total_correct += correct
        total_windows += n

        # Compute avg confidence, handling any remaining NaN
        conf_vals = [probs[i][preds[i]] for i in range(n)]
        conf_vals = [c for c in conf_vals if np.isfinite(c)]
        avg_conf = np.mean(conf_vals) if conf_vals else 0.0

        marker = "✓" if top_pred == lbl else "✗"
        print(f"    {lbl:>6} {len(group):>8,} {n:>5} {top_pred:>8} "
              f"{correct/n*100:>7.1f}% {avg_conf*100:>7.1f}%  {marker}")

    print(f"\n    Overall accuracy: {total_correct}/{total_windows} "
          f"({total_correct/total_windows*100:.1f}%)")

    if total_correct / total_windows < 0.1:
        print("\n    ⚠  Model predicts poorly even on training data!")
        print("    → The model itself is the problem.")
    else:
        print("\n    ✓  Model works on training data → inference feature extraction is wrong.")

if __name__ == "__main__":
    main()
