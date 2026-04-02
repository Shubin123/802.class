#!/usr/bin/env python3
"""
802.11 Encrypted Traffic Classifier — Inference Pipeline
=========================================================
Reads .pcap/.pcapng monitor-mode captures, extracts features,
filters by MAC address, and classifies traffic using a trained 1D ResNet.

Auto-detects feature mode from checkpoint:
  - in_channels ≈ 256  → payload byte mode  (encrypted body bytes)
  - in_channels ≈ 9    → metadata mode      (IAT, frame_len, etc.)

Usage:
    python inference.py
    python inference.py --pcap capture.pcapng
    python inference.py --pcap capture.pcap --mac aa:bb:cc:dd:ee:ff
    python inference.py --checkpoint ../train/checkpoints/best_resnet.pt
"""

import argparse
import sys
import os
import io
import zipfile
from pathlib import Path
from collections import Counter

import numpy as np
import torch
import torch.nn as nn

# ── Import model class from train.py ─────────────────────────────────────────
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "train", str(Path(__file__).parent.resolve() / ".." / "train" / "train.py"))
_train = importlib.util.module_from_spec(_spec)
sys.modules["train"] = _train
_spec.loader.exec_module(_train)
TrafficResNet = _train.TrafficResNet

try:
    from scapy.all import PcapReader, PcapNgReader, RadioTap, Dot11, conf
    conf.verb = 0
except ImportError:
    print("ERROR: scapy is required.  pip install scapy")
    sys.exit(1)

# ── Paths ─────────────────────────────────────────────────────────────────────

WINDOW_SIZE    = 128
PAYLOAD_BYTES  = 256   # must match databuilder.py

SCRIPT_DIR     = Path(__file__).parent.resolve()
CHECKPOINT_DIR = SCRIPT_DIR / ".." / "train" / "checkpoints"

# Labels: 120 classes, sorted lexicographically as strings (matches training)
LABELS = sorted([str(i) for i in range(120)])

# ── Pcap streaming reader ────────────────────────────────────────────────────

def _open_pcap(pcap_path):
    """Open .pcap or .pcapng as a streaming reader (constant memory)."""
    path = str(pcap_path)
    try:
        return PcapNgReader(path)
    except Exception:
        return PcapReader(path)

def find_captures(directory=None):
    d = Path(directory) if directory else SCRIPT_DIR
    return sorted(d.glob("*.pcap")) + sorted(d.glob("*.pcapng"))

# ── MAC scanner (fast raw mode) ──────────────────────────────────────────────

def scan_macs(pcap_path):
    """
    Scan for transmitter MACs in data frames (type_subtype=0x20).
    Uses raw pcap reading to avoid scapy's slow deep dissection.
    """
    from scapy.all import RawPcapReader, RawPcapNgReader
    import struct

    print(f"[scan] Scanning {pcap_path.name} (filter: 0x20) …")
    mac_counts = Counter()
    total = matched = 0

    # Open raw reader (no dissection)
    path = str(pcap_path)
    try:
        reader = RawPcapNgReader(path)
    except Exception:
        reader = RawPcapReader(path)

    for raw_pkt, _metadata in reader:
        total += 1
        if total % 100_000 == 0:
            print(f"  … {total:,} scanned", end='\r')

        data = bytes(raw_pkt)
        if len(data) < 8:
            continue

        # Parse RadioTap header: first 4 bytes = version(1) + pad(1) + length(2)
        rt_len = struct.unpack_from('<H', data, 2)[0]
        dot11_start = rt_len

        if len(data) < dot11_start + 24:
            continue

        # Dot11 Frame Control: 2 bytes at dot11_start
        fc = struct.unpack_from('<H', data, dot11_start)[0]
        frame_type    = (fc >> 2) & 0x3
        frame_subtype = (fc >> 4) & 0xf

        if frame_type != 2 or frame_subtype != 0:
            continue
        matched += 1

        # addr2 (transmitter) is at offset 10 from Dot11 start, 6 bytes
        addr2_offset = dot11_start + 10
        if len(data) < addr2_offset + 6:
            continue
        addr2_bytes = data[addr2_offset:addr2_offset + 6]
        addr2 = ':'.join(f'{b:02x}' for b in addr2_bytes)

        if addr2 != 'ff:ff:ff:ff:ff:ff':
            mac_counts[addr2] += 1

    reader.close()
    print(f"[scan] {total:,} total, {matched:,} data(0x20), {len(mac_counts)} transmitter MACs")
    return dict(mac_counts)

# ── Feature extraction: PAYLOAD BYTES ─────────────────────────────────────────

def extract_payload_bytes(pcap_path, target_mac, payload_bytes=PAYLOAD_BYTES, debug=False):
    """
    Extract encrypted body bytes from each data frame — matches databuilder.py's
    tshark 'data.data' extraction.  Returns (N, payload_bytes) uint8 → float32 array.
    """
    print(f"[feat] Extracting payload bytes ({payload_bytes}B) for {target_mac} …")
    target = target_mac.lower()
    rows = []

    for pkt in _open_pcap(pcap_path):
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        if d.type != 2 or d.subtype != 0:
            continue
        addrs = {(a or '').lower() for a in (d.addr1, d.addr2, d.addr3)}
        if target not in addrs:
            continue

        # Get encrypted body: everything after Dot11 header = CCMP hdr + ciphertext + MIC
        # This matches tshark's 'data.data' for encrypted frames
        body = bytes(d.payload) if d.payload else b''
        arr = np.zeros(payload_bytes, dtype=np.uint8)
        n = min(len(body), payload_bytes)
        if n > 0:
            arr[:n] = np.frombuffer(body[:n], dtype=np.uint8)
        rows.append(arr)

    print(f"[feat] {len(rows):,} frames → {payload_bytes}-byte vectors")

    if not rows:
        return np.zeros((0, payload_bytes), dtype=np.float32)
    result = np.array(rows, dtype=np.float32)

    if debug:
        print(f"\n[debug] Payload byte stats (raw, first 10 positions):")
        print(f"  {'Byte':>6} {'mean':>10} {'std':>10} {'min':>6} {'max':>6}")
        for i in range(min(10, payload_bytes)):
            col = result[:, i]
            print(f"  B{i:>4} {col.mean():>10.2f} {col.std():>10.2f} {col.min():>6.0f} {col.max():>6.0f}")
        print(f"  … ({payload_bytes} total byte positions)")

    return result

# ── Feature extraction: METADATA (legacy 9-feature mode) ─────────────────────

# Training augmentation constants (must match data.py)
RSSI_MEAN   = -65.0
RSSI_SHADOW =  4.0
RSSI_FAST   =  1.5

METADATA_COLS = [
    'iat', 'frame_len', 'seq_num', 'duration',
    'signal_dbm', 'data_rate', 'mcs_index',
    'log_iat', 'frame_len_kb',
]

def extract_metadata(pcap_path, target_mac, debug=False):
    """
    Extract 9 metadata features per frame using tshark (fast, matches training).

    signal_dbm and mcs_index are set to their training mean values
    (augmented values in training are random noise — not class-specific).
    After z-score normalization they become ~0, making the model classify
    on the 7 real features that match training perfectly.
    """
    target = target_mac.lower()
    print(f"[feat] Extracting metadata features for {target} …")

    # ── Try tshark first (C-speed, same tool as training pipeline) ────────
    try:
        arr = _extract_metadata_tshark(pcap_path, target, debug)
        if arr is not None:
            return arr
    except Exception as e:
        print(f"[feat] tshark unavailable ({e}), falling back to scapy …")

    # ── Fallback: scapy (slow but always works) ──────────────────────────
    return _extract_metadata_scapy(pcap_path, target, debug)


def _extract_metadata_tshark(pcap_path, target, debug=False):
    """Fast extraction using tshark — same tool as training pipeline."""
    import subprocess, io
    import pandas as pd

    # Combined filter: type_subtype=0x20 AND target MAC in any address field
    mac_filter = (f"wlan.fc.type_subtype == 0x0020 && wlan.addr == {target}")

    fields = [
        "frame.time_epoch", "frame.len", "wlan.seq",
        "wlan.duration", "radiotap.datarate",
    ]

    cmd = [
        "tshark", "-r", str(pcap_path),
        "-Y", mac_filter,
        "-T", "fields",
        "-E", "separator=,",
        "-E", "header=y",
        "-E", "occurrence=f",
    ]
    for f in fields:
        cmd.extend(["-e", f])

    print(f"[feat] Running tshark (filter: 0x20 + MAC) …")
    r = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)

    df = pd.read_csv(io.StringIO(r.stdout))
    if df.empty:
        return np.zeros((0, len(METADATA_COLS)), dtype=np.float32)

    df.fillna({
        "wlan.seq": 0, "wlan.duration": 0, "radiotap.datarate": 0,
    }, inplace=True)

    records = []
    prev_ts = None
    for _, row in df.iterrows():
        ts = float(row["frame.time_epoch"])
        iat = (ts - prev_ts) if prev_ts is not None else 0.0
        prev_ts = ts
        frame_len = int(row["frame.len"])

        records.append([
            iat,
            frame_len,
            int(row["wlan.seq"]),
            int(row["wlan.duration"]),
            RSSI_MEAN,                            # signal_dbm = training mean
            float(row["radiotap.datarate"]),
            5.0,                                   # mcs_index = training mean
            np.log1p(iat),
            frame_len / 1024.0,
        ])

    n_feats = len(METADATA_COLS)
    n_frames = len(records)
    print(f"[feat] {n_frames:,} frames → {n_feats} metadata features (tshark)")
    if not records:
        return np.zeros((0, n_feats), dtype=np.float32)

    arr = np.array(records, dtype=np.float32)
    print(f"[feat] signal_dbm={RSSI_MEAN}, mcs_index=5 (training means → neutral after z-score)")

    if debug:
        print(f"\n[debug] Feature statistics (raw, before normalization):")
        print(f"  {'Feature':>15} {'mean':>12} {'std':>12} {'min':>12} {'max':>12}")
        print(f"  {'-'*63}")
        for i, name in enumerate(METADATA_COLS):
            col = arr[:, i]
            print(f"  {name:>15} {col.mean():>12.4f} {col.std():>12.4f} {col.min():>12.4f} {col.max():>12.4f}")

    return arr


def _extract_metadata_scapy(pcap_path, target, debug=False):
    """Fallback: scapy-based extraction (slow but always works)."""
    print(f"[feat] Using scapy fallback (slower) …")
    records = []
    prev_ts = None
    count = 0

    for pkt in _open_pcap(pcap_path):
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        if d.type != 2 or d.subtype != 0:
            continue
        addrs = {(a or '').lower() for a in (d.addr1, d.addr2, d.addr3)}
        if target not in addrs:
            continue

        ts  = float(pkt.time)
        iat = (ts - prev_ts) if prev_ts is not None else 0.0
        prev_ts = ts
        frame_len  = len(pkt)
        seq_num    = (d.SC >> 4) if d.SC else 0
        duration   = d.ID if d.ID else 0

        data_rate = 0.0
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            try:
                if rt.Rate is not None:
                    data_rate = float(rt.Rate)
            except (AttributeError, TypeError):
                pass

        records.append([iat, frame_len, seq_num, duration,
                        RSSI_MEAN, data_rate, 5.0,
                        np.log1p(iat), frame_len / 1024.0])
        count += 1
        if count % 5000 == 0:
            print(f"  … {count:,} frames", end='\r')

    n_feats = len(METADATA_COLS)
    print(f"[feat] {len(records):,} frames → {n_feats} metadata features (scapy)")
    if not records:
        return np.zeros((0, n_feats), dtype=np.float32)

    arr = np.array(records, dtype=np.float32)
    print(f"[feat] signal_dbm={RSSI_MEAN}, mcs_index=5 (training means → neutral after z-score)")
    return arr

# ── Normalization stats ───────────────────────────────────────────────────────

def compute_norm_stats(num_features, training_parquet=None):
    """
    Compute per-feature mean/std from the training parquet.
    Auto-selects the right parquet based on num_features:
      - small (≤20): metadata parquet (dataset.parquet / .zip)
      - large (>20):  payload parquet (output.parquet)
    """
    import pandas as pd

    data_dir = SCRIPT_DIR / ".." / "data"
    zip_path = data_dir / "dataset_output" / "dataset.parquet.zip"

    df = None

    # If user specified a path, use it
    if training_parquet:
        p = Path(training_parquet)
        if p.exists():
            print(f"[norm] Loading {p.name} …")
            df = pd.read_parquet(p)

    # Otherwise, pick based on mode
    if df is None:
        if num_features <= 20:
            # Metadata mode → prefer dataset.parquet(.zip)
            dp = data_dir / "dataset_output" / "dataset.parquet"
            if dp.exists():
                print(f"[norm] Loading {dp.name} (metadata mode) …")
                df = pd.read_parquet(dp)
            elif zip_path.exists():
                print(f"[norm] Loading {zip_path.name} (metadata mode) …")
                zf = zipfile.ZipFile(zip_path)
                with zf.open(zf.namelist()[0]) as f:
                    df = pd.read_parquet(io.BytesIO(f.read()))
        else:
            # Payload mode → prefer output.parquet
            op = data_dir / "output.parquet"
            if op.exists():
                print(f"[norm] Loading {op.name} (payload mode) …")
                df = pd.read_parquet(op)

    # Fallback: try anything we can find
    if df is None:
        for p in [data_dir / "output.parquet",
                  data_dir / "dataset_output" / "dataset.parquet"]:
            if p.exists():
                print(f"[norm] Fallback: loading {p.name} …")
                df = pd.read_parquet(p)
                break
        else:
            if zip_path.exists():
                print(f"[norm] Fallback: loading {zip_path.name} …")
                zf = zipfile.ZipFile(zip_path)
                with zf.open(zf.namelist()[0]) as f:
                    df = pd.read_parquet(io.BytesIO(f.read()))
            else:
                raise FileNotFoundError(f"No training parquet found in {data_dir}")

    # Replicate train.py's feature selection logic exactly
    exclude = {'label', 'timestamp', '_blk', '_fid'}
    feature_cols = [c for c in df.columns if c not in exclude]

    # Expand list/array columns (like 'payload') into individual numeric columns
    parts = []
    for c in feature_cols:
        sample = df[c].iloc[0]
        if isinstance(sample, (list, np.ndarray)):
            arr = np.array(df[c].tolist(), dtype=np.float32)
            part = pd.DataFrame(arr, columns=[f"{c}_{i}" for i in range(arr.shape[1])])
            parts.append(part)
        else:
            parts.append(df[[c]])
    expanded_df = pd.concat(parts, axis=1)

    # Filter constants (same as train.py)
    valid_cols = [c for c in expanded_df.columns if expanded_df[c].nunique() > 1]
    print(f"[norm] {len(valid_cols)} valid features (from {len(expanded_df.columns)} total)")

    # Use only the first num_features valid columns to match checkpoint
    if len(valid_cols) > num_features:
        print(f"[norm] Truncating {len(valid_cols)} → {num_features} features to match checkpoint")
        valid_cols = valid_cols[:num_features]
    elif len(valid_cols) < num_features:
        print(f"[norm] WARNING: only {len(valid_cols)} valid features, checkpoint expects {num_features}")

    feats = expanded_df[valid_cols].values.astype(np.float32)
    feats = np.where(np.isfinite(feats), feats, 0.0)

    mean = feats.mean(axis=0)
    std  = feats.std(axis=0) + 1e-8

    # Cache alongside checkpoint
    stats_path = CHECKPOINT_DIR / f"norm_stats_{num_features}.npz"
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    np.savez(stats_path, mean=mean, std=std)
    print(f"[norm] Saved → {stats_path}  ({len(mean)} features)")
    return mean, std


def load_norm_stats(num_features, training_parquet=None):
    """Load cached norm stats or compute from training data."""
    stats_path = CHECKPOINT_DIR / f"norm_stats_{num_features}.npz"
    if stats_path.exists():
        d = np.load(stats_path)
        m, s = d['mean'], d['std']
        if len(m) == num_features:
            return m, s
    return compute_norm_stats(num_features, training_parquet)

# ── Model loading with auto-detection ─────────────────────────────────────────

def load_model(ckpt=None):
    """
    Load checkpoint and auto-detect in_channels and num_classes
    from the weight shapes. No hardcoded constants.
    """
    if ckpt is None:
        # Search for checkpoints
        for name in sorted(CHECKPOINT_DIR.glob("best_*.pt"), key=lambda p: p.stat().st_mtime, reverse=True):
            ckpt = name
            break
        if ckpt is None:
            raise FileNotFoundError(f"No best_*.pt checkpoint in {CHECKPOINT_DIR}")
    ckpt = Path(ckpt)

    dev = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    # Peek into checkpoint to discover architecture params
    sd = torch.load(ckpt, map_location=dev, weights_only=True)

    # Auto-detect in_channels and num_classes from weight shapes
    # TrafficResNet has 'stem.0.weight' and 'fc.weight'
    if 'stem.0.weight' in sd:
        in_channels = sd['stem.0.weight'].shape[1]
    else:
        # Find first conv weight (shape: out_ch, in_ch, kernel)
        for k, v in sd.items():
            if 'weight' in k and v.ndim == 3:
                in_channels = v.shape[1]
                break
        else:
            raise KeyError(f"Cannot detect in_channels from {ckpt.name}. Keys: {list(sd.keys())[:5]}")

    if 'fc.weight' in sd:
        num_classes = sd['fc.weight'].shape[0]
    else:
        # Find last linear weight (shape: out, in)
        for k in reversed(list(sd.keys())):
            if 'weight' in k and sd[k].ndim == 2:
                num_classes = sd[k].shape[0]
                break
        else:
            raise KeyError(f"Cannot detect num_classes from {ckpt.name}")

    model = TrafficResNet(num_classes=num_classes, in_channels=in_channels).to(dev)
    model.load_state_dict(sd)
    model.eval()

    print(f"[model] Loaded {ckpt.name} on {dev}  "
          f"(in_channels={in_channels}, classes={num_classes})")

    return model, dev, in_channels, num_classes

# ── Inference ─────────────────────────────────────────────────────────────────

def infer(model, dev, features, mean, std, num_features, ws=WINDOW_SIZE):
    n = len(features)
    nw = n // ws
    if nw == 0:
        if n == 0:
            return np.array([]), np.array([])
        pad = np.zeros((ws, num_features), np.float32)
        pad[:n] = features
        features = pad
        nw = 1
    else:
        features = features[:nw * ws]

    # (N, W, F) → (N, F, W) for Conv1d
    w = features.reshape(nw, ws, num_features).transpose(0, 2, 1)

    # Z-score normalize per feature, clip to ±10 (matches training)
    w = np.clip((w - mean.reshape(1, -1, 1)) / std.reshape(1, -1, 1), -10, 10)

    with torch.no_grad():
        logits = model(torch.from_numpy(w).float().to(dev))
        probs  = torch.softmax(logits, 1)
    return logits.argmax(1).cpu().numpy(), probs.cpu().numpy()

# ── Display ───────────────────────────────────────────────────────────────────

def show_mac_table(mc):
    items = sorted(mc.items(), key=lambda x: -x[1])
    print(f"\n{'#':>4}   {'MAC Address':<20} {'Frames':>10}")
    print("-" * 40)
    for i, (m, c) in enumerate(items):
        print(f"{i:>4}   {m:<20} {c:>10,}")
    return items

def show_results(preds, confs, n_pkts, num_classes):
    labels = sorted([str(i) for i in range(num_classes)])
    nw = len(preds)
    if nw == 0:
        print("No predictions."); return
    print(f"\n{'='*65}")
    print(f"  RESULTS — {n_pkts:,} packets → {nw} windows (size {WINDOW_SIZE})")
    print(f"{'='*65}")
    print(f"  {'Win':>4} {'Class':>6} {'Label':>6} {'Conf':>7}")
    for i, (p, c) in enumerate(zip(preds, confs)):
        lbl = labels[p] if p < len(labels) else str(p)
        print(f"  {i:>4} {p:>6} {lbl:>6} {c[p]*100:>6.1f}%  {'█'*int(c[p]*30)}")
    counts = Counter(preds)
    top = counts.most_common(10)
    mx = top[0][1]
    print(f"\n  Top classes:")
    for cls, cnt in top:
        bar = '█' * int(cnt/mx*25)
        pct = cnt/nw*100
        lbl = labels[cls] if cls < len(labels) else str(cls)
        print(f"  Class {cls:>3} (label {lbl:>3}): {bar:<25} {cnt}/{nw} ({pct:.0f}%)")
    maj = top[0][0]
    maj_lbl = labels[maj] if maj < len(labels) else str(maj)
    print(f"\n  ► Majority: class {maj} (label {maj_lbl})")

def plot_results(preds, confs, num_classes, out=None):
    try:
        import matplotlib; matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        return
    labels = sorted([str(i) for i in range(num_classes)])
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 7))
    fig.suptitle('802.11 Traffic Classification', fontweight='bold')
    counts = Counter(preds)
    top = counts.most_common(10)
    ax1.barh([f"C{c} (L{labels[c] if c<len(labels) else c})" for c,_ in top],
             [n for _,n in top], color='steelblue')
    ax1.set_xlabel('Windows'); ax1.set_title('Top Predicted Classes'); ax1.invert_yaxis()
    mc = [confs[i][preds[i]] for i in range(len(preds))]
    ax2.fill_between(range(len(mc)), mc, alpha=.3, color='teal')
    ax2.plot(mc, color='teal'); ax2.set_ylabel('Confidence'); ax2.set_xlabel('Window')
    ax2.set_title('Per-Window Confidence'); ax2.set_ylim(0, 1.05)
    plt.tight_layout()
    p = Path(out) if out else SCRIPT_DIR / "results.png"
    plt.savefig(p, dpi=150); plt.close()
    print(f"  Chart → {p}")

# ── CLI ───────────────────────────────────────────────────────────────────────

def pick(items, prompt):
    while True:
        try:
            r = input(f"\n{prompt} [0-{len(items)-1}] (q=quit): ").strip()
            if r.lower() in ('q','quit','exit'): sys.exit(0)
            i = int(r)
            if 0 <= i < len(items): return i
        except (ValueError, EOFError, KeyboardInterrupt):
            pass
        print(f"  Enter 0–{len(items)-1}")

def main():
    ap = argparse.ArgumentParser(description="802.11 Traffic Classifier — Inference")
    ap.add_argument("--pcap",       type=str, help="Capture file (.pcap/.pcapng)")
    ap.add_argument("--mac",        type=str, help="Target MAC (skip interactive)")
    ap.add_argument("--checkpoint", type=str, help="Model checkpoint path")
    ap.add_argument("--training-data", type=str, help="Training parquet for norm stats")
    ap.add_argument("--window-size",type=int, default=WINDOW_SIZE)
    ap.add_argument("--no-plot",    action="store_true")
    ap.add_argument("--debug",      action="store_true", help="Dump feature stats")
    args = ap.parse_args()

    print("="*65)
    print("  802.11 Encrypted Traffic Classifier — Inference")
    print("="*65)

    # 1 — load model first (to know what features to extract)
    model, dev, in_channels, num_classes = load_model(args.checkpoint)

    # Determine extraction mode from in_channels
    if in_channels <= 20:
        mode = "metadata"
        print(f"[mode] Metadata features ({in_channels} channels)")
    else:
        mode = "payload"
        print(f"[mode] Payload bytes ({in_channels} channels)")

    # 2 — pick capture
    if args.pcap:
        pcap = Path(args.pcap)
        if not pcap.exists(): print(f"Not found: {pcap}"); sys.exit(1)
    else:
        caps = find_captures()
        if not caps: print("No captures found."); sys.exit(1)
        if len(caps) == 1:
            pcap = caps[0]; print(f"\nAuto-selected {pcap.name}")
        else:
            for i,c in enumerate(caps):
                print(f"  [{i}] {c.name}  ({c.stat().st_size/1e6:.1f} MB)")
            pcap = caps[pick(caps, "Select capture")]
    print(f"► {pcap.name} ({pcap.stat().st_size/1e6:.1f} MB)")

    # 3 — scan MACs
    mc = scan_macs(pcap)
    if not mc: print("No data frames found."); sys.exit(1)
    items = show_mac_table(mc)

    # 4 — pick MAC
    if args.mac:
        target = args.mac.lower()
    else:
        target = items[pick(items, "Select MAC")][0]
    print(f"► MAC: {target}")

    # 5 — extract features (auto mode)
    if mode == "payload":
        feats = extract_payload_bytes(pcap, target, payload_bytes=in_channels, debug=args.debug)
    else:
        feats = extract_metadata(pcap, target, debug=args.debug)

    if len(feats) == 0: print("No frames for this MAC."); sys.exit(1)

    # 6 — load normalization stats
    mean, std = load_norm_stats(in_channels, args.training_data)

    # 7 — inference
    preds, confs = infer(model, dev, feats, mean, std, in_channels, args.window_size)

    # 8 — results
    show_results(preds, confs, len(feats), num_classes)
    if not args.no_plot:
        plot_results(preds, confs, num_classes)

if __name__ == "__main__":
    main()
