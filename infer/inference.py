#!/usr/bin/env python3
"""
802.11 Encrypted Traffic Classifier — Inference Pipeline
=========================================================
Reads .pcap/.pcapng monitor-mode captures, extracts behavioral features,
filters by MAC address, and classifies traffic using a trained 1D ResNet.

Usage:
    python inference.py
    python inference.py --pcap capture.pcapng
    python inference.py --pcap capture.pcap --mac aa:bb:cc:dd:ee:ff
    python inference.py --checkpoint ../train/checkpoints/best_resnet40.pt
"""

import argparse
import sys
import os
import io
import zipfile
import textwrap
from pathlib import Path
from collections import Counter

import numpy as np
import torch
import torch.nn as nn

try:
    from scapy.all import rdpcap, RadioTap, Dot11, conf
    conf.verb = 0  # silence scapy
except ImportError:
    print("ERROR: scapy is required.  pip install scapy")
    sys.exit(1)

# ── Constants (must match training pipeline) ──────────────────────────────────

FEATURE_COLS = [
    'iat', 'frame_len', 'seq_num', 'duration',
    'signal_dbm', 'data_rate', 'mcs_index',
    'log_iat', 'frame_len_kb',
]
NUM_FEATURES  = len(FEATURE_COLS)   # 9
NUM_CLASSES   = 120
WINDOW_SIZE   = 128
LABELS        = sorted([str(i) for i in range(120)])  # lexicographic

SCRIPT_DIR       = Path(__file__).parent.resolve()
CHECKPOINT_DIR   = SCRIPT_DIR / ".." / "train" / "checkpoints"
NORM_STATS_PATH  = CHECKPOINT_DIR / "norm_stats.npz"
TRAINING_ZIP     = SCRIPT_DIR / ".." / "data" / "dataset_output" / "dataset.parquet.zip"

# ── Model (identical to train.py) ─────────────────────────────────────────────

class ResBlock1D(nn.Module):
    def __init__(self, ch):
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv1d(ch, ch, 3, padding=1, bias=False), nn.GroupNorm(4, ch), nn.ReLU(),
            nn.Conv1d(ch, ch, 3, padding=1, bias=False), nn.GroupNorm(4, ch),
        )
        self.relu = nn.ReLU()
    def forward(self, x):
        return self.relu(x + self.net(x))

class TrafficResNet(nn.Module):
    def __init__(self, num_classes, in_channels):
        super().__init__()
        self.stem = nn.Sequential(
            nn.Conv1d(in_channels, 64, 7, padding=3, bias=False),
            nn.GroupNorm(4, 64), nn.ReLU(), nn.MaxPool1d(2),
        )
        self.layer1 = ResBlock1D(64)
        self.layer2 = nn.Sequential(
            nn.Conv1d(64, 128, 3, stride=2, padding=1, bias=False),
            nn.GroupNorm(8, 128), nn.ReLU(), ResBlock1D(128),
        )
        self.layer3 = nn.Sequential(
            nn.Conv1d(128, 256, 3, stride=2, padding=1, bias=False),
            nn.GroupNorm(8, 256), nn.ReLU(), ResBlock1D(256),
        )
        self.pool = nn.AdaptiveAvgPool1d(1)
        self.fc   = nn.Linear(256, num_classes)

    def forward(self, x):
        x = self.stem(x)
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.layer3(x)
        return self.fc(self.pool(x).flatten(1))

# ── Normalization stats ───────────────────────────────────────────────────────

def _compute_norm_stats():
    """Compute per-feature mean/std from the training parquet (one-time)."""
    import pandas as pd
    print("[norm] Computing normalization stats from training data …")
    if TRAINING_ZIP.exists():
        zf = zipfile.ZipFile(TRAINING_ZIP)
        with zf.open(zf.namelist()[0]) as f:
            df = pd.read_parquet(io.BytesIO(f.read()))
    else:
        alt = SCRIPT_DIR / ".." / "data" / "dataset_output" / "dataset.parquet"
        if not alt.exists():
            raise FileNotFoundError(f"Cannot find training data at {TRAINING_ZIP} or {alt}")
        df = pd.read_parquet(alt)

    available = [c for c in FEATURE_COLS if c in df.columns]
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=available)
    feats = df[available].values.astype(np.float32)
    mean  = feats.mean(axis=0)
    std   = feats.std(axis=0) + 1e-8
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    np.savez(NORM_STATS_PATH, mean=mean, std=std)
    print(f"[norm] Saved → {NORM_STATS_PATH}")
    return mean, std

def load_norm_stats():
    if NORM_STATS_PATH.exists():
        d = np.load(NORM_STATS_PATH)
        return d['mean'], d['std']
    return _compute_norm_stats()

# ── Pcap helpers (scapy – handles .pcap and .pcapng) ──────────────────────────

def find_captures(directory=None):
    d = Path(directory) if directory else SCRIPT_DIR
    return sorted(d.glob("*.pcap")) + sorted(d.glob("*.pcapng"))

def scan_macs(pcap_path):
    """Return {mac: data-frame count} from a monitor-mode capture."""
    print(f"[scan] Reading {pcap_path.name} …")
    pkts = rdpcap(str(pcap_path))
    mac_counts = Counter()
    for pkt in pkts:
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        if d.type != 2:          # data frames only
            continue
        for a in (d.addr1, d.addr2, d.addr3):
            if a and a.lower() != 'ff:ff:ff:ff:ff:ff':
                mac_counts[a.lower()] += 1
    print(f"[scan] {len(pkts):,} packets total, {len(mac_counts)} unique MACs in data frames")
    return dict(mac_counts)

def extract_features(pcap_path, target_mac):
    """Extract the 9 training features for frames involving *target_mac*."""
    pkts    = rdpcap(str(pcap_path))
    target  = target_mac.lower()
    records = []
    prev_ts = None

    for pkt in pkts:
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        if d.type != 2:
            continue
        addrs = {(a or '').lower() for a in (d.addr1, d.addr2, d.addr3)}
        if target not in addrs:
            continue

        ts  = float(pkt.time)
        iat = (ts - prev_ts) if prev_ts is not None else 0.0
        prev_ts = ts

        frame_len = len(pkt)
        seq_num   = (d.SC >> 4) if d.SC else 0
        duration  = d.ID if d.ID else 0

        # RadioTap fields with safe fallbacks
        signal_dbm = -65.0
        data_rate  = 0.0
        mcs_index  = 0
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            try:
                if rt.dBm_AntSignal is not None:
                    signal_dbm = float(rt.dBm_AntSignal)
            except (AttributeError, TypeError):
                pass
            try:
                if rt.Rate is not None:
                    data_rate = float(rt.Rate)
            except (AttributeError, TypeError):
                pass
            try:
                if rt.MCS_index is not None:
                    mcs_index = int(rt.MCS_index)
            except (AttributeError, TypeError):
                # derive from signal (same ladder as training augmentation)
                for thresh, idx in [(-55,7),(-62,6),(-68,5),(-74,4),(-77,3),(-82,2),(-87,1)]:
                    if signal_dbm >= thresh:
                        mcs_index = idx
                        break

        records.append([
            iat, frame_len, seq_num, duration,
            signal_dbm, data_rate, mcs_index,
            np.log1p(iat), frame_len / 1024.0,
        ])

    print(f"[feat] {len(records):,} data frames extracted for {target_mac}")
    return np.array(records, dtype=np.float32).reshape(-1, NUM_FEATURES) if records \
        else np.zeros((0, NUM_FEATURES), dtype=np.float32)

# ── Inference ─────────────────────────────────────────────────────────────────

def load_model(ckpt=None):
    if ckpt is None:
        for name in ("best_resnet40.pt", "best_resnet.pt.600epoch", "best_resnet.pt.300epoch"):
            p = CHECKPOINT_DIR / name
            if p.exists():
                ckpt = p; break
        else:
            raise FileNotFoundError(f"No checkpoint in {CHECKPOINT_DIR}")
    ckpt = Path(ckpt)
    dev  = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = TrafficResNet(NUM_CLASSES, NUM_FEATURES).to(dev)
    model.load_state_dict(torch.load(ckpt, map_location=dev, weights_only=True))
    model.eval()
    print(f"[model] Loaded {ckpt.name} on {dev}  ({NUM_FEATURES}→{NUM_CLASSES})")
    return model, dev

def infer(model, dev, features, mean, std, ws=WINDOW_SIZE):
    n = len(features)
    nw = n // ws
    if nw == 0:
        if n == 0:
            return np.array([]), np.array([])
        pad = np.zeros((ws, NUM_FEATURES), np.float32)
        pad[:n] = features
        features = pad
        nw = 1
    else:
        features = features[:nw * ws]

    w = features.reshape(nw, ws, NUM_FEATURES).transpose(0, 2, 1)   # (N,F,W)
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

def show_results(preds, confs, n_pkts):
    nw = len(preds)
    if nw == 0:
        print("No predictions."); return
    print(f"\n{'='*65}")
    print(f"  RESULTS — {n_pkts:,} packets → {nw} windows (size {WINDOW_SIZE})")
    print(f"{'='*65}")
    # per-window
    print(f"  {'Win':>4} {'Class':>6} {'Label':>6} {'Conf':>7}")
    for i, (p, c) in enumerate(zip(preds, confs)):
        print(f"  {i:>4} {p:>6} {LABELS[p]:>6} {c[p]*100:>6.1f}%  {'█'*int(c[p]*30)}")
    # aggregate
    counts = Counter(preds)
    top = counts.most_common(10)
    mx = top[0][1]
    print(f"\n  Top classes:")
    for cls, cnt in top:
        bar = '█' * int(cnt/mx*25)
        pct = cnt/nw*100
        print(f"  Class {cls:>3} (label {LABELS[cls]:>3}): {bar:<25} {cnt}/{nw} ({pct:.0f}%)")
    maj = top[0][0]
    print(f"\n  ► Majority: class {maj} (label {LABELS[maj]})")

def plot_results(preds, confs, out=None):
    try:
        import matplotlib; matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        return
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 7))
    fig.suptitle('802.11 Traffic Classification', fontweight='bold')
    counts = Counter(preds)
    top = counts.most_common(10)
    ax1.barh([f"C{c} (L{LABELS[c]})" for c,_ in top], [n for _,n in top], color='steelblue')
    ax1.set_xlabel('Windows'); ax1.set_title('Top Predicted Classes'); ax1.invert_yaxis()
    mc = [confs[i][preds[i]] for i in range(len(preds))]
    ax2.fill_between(range(len(mc)), mc, alpha=.3, color='teal')
    ax2.plot(mc, color='teal'); ax2.set_ylabel('Confidence'); ax2.set_xlabel('Window')
    ax2.set_title('Per-Window Confidence'); ax2.set_ylim(0, 1.05)
    plt.tight_layout()
    p = Path(out) if out else SCRIPT_DIR / "results.png"
    plt.savefig(p, dpi=150); plt.close()
    print(f"  Chart → {p}")

# ── Interactive CLI ───────────────────────────────────────────────────────────

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
    ap.add_argument("--window-size",type=int, default=WINDOW_SIZE)
    ap.add_argument("--no-plot",    action="store_true")
    args = ap.parse_args()

    print("="*65)
    print("  802.11 Encrypted Traffic Classifier — Inference")
    print("="*65)

    # 1 — pick capture
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

    # 2 — scan MACs
    mc = scan_macs(pcap)
    if not mc: print("No data frames found."); sys.exit(1)
    items = show_mac_table(mc)

    # 3 — pick MAC
    if args.mac:
        target = args.mac.lower()
    else:
        target = items[pick(items, "Select MAC")][0]
    print(f"► MAC: {target}")

    # 4 — extract features
    feats = extract_features(pcap, target)
    if len(feats) == 0: print("No frames for this MAC."); sys.exit(1)

    # 5 — load model + norm stats
    model, dev = load_model(args.checkpoint)
    mean, std  = load_norm_stats()

    # 6 — inference
    preds, confs = infer(model, dev, feats, mean, std, args.window_size)

    # 7 — results
    show_results(preds, confs, len(feats))
    if not args.no_plot:
        plot_results(preds, confs)

if __name__ == "__main__":
    main()
