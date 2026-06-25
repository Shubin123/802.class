#!/usr/bin/env python3
"""
eval_real.py — Real-data test harness (sim-to-real gap meter)
=============================================================
Runs a TRAINED checkpoint against LABELED real over-the-air monitor-mode
captures and reports how well it actually classifies, versus a chance
baseline. This is the go/no-go gate for the re-haul: the current model was
trained entirely on mac80211_hwsim-simulated data with fabricated radio
features, so the expectation here is ~chance. This file turns that
expectation into a measured number.

It deliberately reuses inference.py's feature extraction, normalization, and
inference code so the feature contract is IDENTICAL to the deployed path —
otherwise the measured gap would just be a second pipeline's bug, not the
model's.

Manifest (CSV, header required):
    pcap,mac,label,session
    sessions/youtube__s01.pcap,aa:bb:cc:dd:ee:ff,132,s01
    sessions/netflix__s01.pcap,aa:bb:cc:dd:ee:ff,83,s01
  - pcap    : path to a monitor-mode capture, relative to the manifest file
  - mac     : the client (DUT) MAC whose data frames to classify
  - label   : ground-truth class. With --label-mode cstnet (default) this is
              the CSTNET class id as used by the .npy source ("0".."119");
              the lexicographic remap that training applied is handled here.
              With --label-mode index it is the model's output index directly.
  - session : (optional) groups windows for a per-session majority vote. If
              omitted, the pcap path is used as the session id.

Usage:
    python eval_real.py \
        --manifest ../data/real/manifest.csv \
        --checkpoint ../train/checkpoints/best_resnet.pt.600epoch
"""

import argparse
import json
import sys
from pathlib import Path
from collections import Counter, defaultdict

import numpy as np

# ─────────────────────────────────────────────────────────────
# Reuse inference.py verbatim (identical feature contract)
# ─────────────────────────────────────────────────────────────
import importlib.util

INFER_DIR = Path(__file__).parent.resolve()
_spec = importlib.util.spec_from_file_location("inference", str(INFER_DIR / "inference.py"))
inference = importlib.util.module_from_spec(_spec)
sys.modules["inference"] = inference
_spec.loader.exec_module(inference)

WINDOW_SIZE = inference.WINDOW_SIZE


# ─────────────────────────────────────────────────────────────
# Label mapping
# ─────────────────────────────────────────────────────────────
def build_label_maps(num_classes, mode):
    """
    Training remapped labels via sorted(df['label'].unique()) on STRING labels,
    i.e. lexicographic order: "0","1","10","100","101",...  So model output
    index != integer label. Reproduce that mapping so manifest ground truth
    lines up with model predictions.

    Returns (to_model_idx, to_cstnet) where:
      to_model_idx(raw_label) -> int model index
      to_cstnet(model_idx)    -> str human-facing CSTNET label
    """
    cstnet_sorted = sorted([str(i) for i in range(num_classes)])  # matches train.py
    idx_of = {lbl: i for i, lbl in enumerate(cstnet_sorted)}

    if mode == "index":
        return (lambda raw: int(raw)), (lambda i: str(i))

    def to_model_idx(raw):
        key = str(raw).strip()
        if key not in idx_of:
            raise KeyError(
                f"label '{key}' is not a CSTNET id in 0..{num_classes-1}. "
                f"Use --label-mode index if your manifest already holds model indices."
            )
        return idx_of[key]

    return to_model_idx, (lambda i: cstnet_sorted[i] if 0 <= i < num_classes else str(i))


# ─────────────────────────────────────────────────────────────
# Feature extraction dispatch (mirror inference.py's mode pick)
# ─────────────────────────────────────────────────────────────
def extract_for_mode(pcap, mac, in_channels, debug=False):
    if in_channels <= 20:
        return inference.extract_metadata(pcap, mac, debug=debug)
    return inference.extract_payload_bytes(pcap, mac, payload_bytes=in_channels, debug=debug)


# ─────────────────────────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────────────────────────
def macro_f1(gt, pred):
    """Macro-averaged F1 over the classes that appear in ground truth."""
    gt = np.asarray(gt)
    pred = np.asarray(pred)
    classes = np.unique(gt)
    f1s = []
    for c in classes:
        tp = int(np.sum((pred == c) & (gt == c)))
        fp = int(np.sum((pred == c) & (gt != c)))
        fn = int(np.sum((pred != c) & (gt == c)))
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        f1s.append(f1)
    return float(np.mean(f1s)) if f1s else 0.0


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Real-data test harness for the 802.11 classifier")
    ap.add_argument("--manifest", required=True, help="CSV: pcap,mac,label[,session]")
    ap.add_argument("--checkpoint", default=str(INFER_DIR / ".." / "train" / "checkpoints" / "best_resnet.pt.600epoch"),
                    help="Model checkpoint (the .pt.600epoch files do NOT match best_*.pt, so pass explicitly)")
    ap.add_argument("--training-data", default=None, help="Training parquet for norm stats (optional; norm_stats_N.npz used if present)")
    ap.add_argument("--label-mode", choices=["cstnet", "index"], default="cstnet")
    ap.add_argument("--window-size", type=int, default=WINDOW_SIZE)
    ap.add_argument("--out", default=None, help="Write a JSON report here")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    import pandas as pd

    manifest_path = Path(args.manifest).resolve()
    if not manifest_path.exists():
        print(f"Manifest not found: {manifest_path}")
        sys.exit(1)
    manifest_dir = manifest_path.parent
    rows = pd.read_csv(manifest_path, dtype=str).fillna("")
    required = {"pcap", "mac", "label"}
    if not required.issubset(rows.columns):
        print(f"Manifest must have columns {sorted(required)} (+ optional 'session'). Got: {list(rows.columns)}")
        sys.exit(1)

    print("=" * 68)
    print("  Real-data test harness — measuring the sim-to-real gap")
    print("=" * 68)

    # 1 — model
    ckpt = Path(args.checkpoint)
    if not ckpt.exists():
        cands = sorted(Path(args.checkpoint).parent.glob("best_resnet*"),
                       key=lambda p: p.stat().st_mtime, reverse=True) if Path(args.checkpoint).parent.exists() else []
        if not cands:
            print(f"Checkpoint not found: {ckpt}")
            sys.exit(1)
        ckpt = cands[0]
        print(f"[model] '{args.checkpoint}' missing; using {ckpt.name}")
    model, dev, in_channels, num_classes = inference.load_model(ckpt)
    mode = "metadata" if in_channels <= 20 else "payload"
    print(f"[mode]  {mode} ({in_channels} channels), {num_classes} classes")

    # 2 — norm stats (same as inference.py)
    mean, std = inference.load_norm_stats(in_channels, args.training_data)

    # 3 — label maps
    to_model_idx, to_cstnet = build_label_maps(num_classes, args.label_mode)

    # 4 — per-capture inference
    win_gt, win_pred, win_conf = [], [], []
    session_preds = defaultdict(list)   # session -> [pred_idx, ...]
    session_gt = {}                     # session -> gt_idx
    per_capture = []

    for _, r in rows.iterrows():
        pcap = Path(r["pcap"])
        if not pcap.is_absolute():
            pcap = (manifest_dir / pcap).resolve()
        mac = r["mac"].strip().lower()
        session = r["session"].strip() if "session" in rows.columns and r["session"].strip() else str(pcap)
        try:
            gt_idx = to_model_idx(r["label"])
        except KeyError as e:
            print(f"  ! skipping {pcap.name}: {e}")
            continue

        if not pcap.exists():
            print(f"  ! skipping (missing pcap): {pcap}")
            continue

        print(f"\n► {pcap.name}  mac={mac}  label={r['label']} (model idx {gt_idx})")
        feats = extract_for_mode(pcap, mac, in_channels, debug=args.debug)
        if len(feats) == 0:
            print(f"  ! no data frames for {mac} — nothing to classify")
            per_capture.append({"pcap": str(pcap), "label": r["label"], "windows": 0, "acc": None})
            continue

        preds, confs = inference.infer(model, dev, feats, mean, std, in_channels, args.window_size)
        preds = np.asarray(preds, dtype=int)
        if preds.size == 0:
            print("  ! fewer than one window of frames")
            continue

        cap_acc = float(np.mean(preds == gt_idx))
        vote = Counter(preds.tolist()).most_common(1)[0][0]
        print(f"  {len(preds)} windows | window-acc {cap_acc*100:5.1f}% | "
              f"majority pred = idx {vote} (CSTNET {to_cstnet(vote)})")

        for i, p in enumerate(preds):
            win_gt.append(gt_idx)
            win_pred.append(int(p))
            win_conf.append(float(confs[i][p]) if confs is not None and len(confs) > i else float("nan"))
            session_preds[session].append(int(p))
        session_gt[session] = gt_idx
        per_capture.append({"pcap": str(pcap), "label": r["label"], "model_idx": gt_idx,
                            "windows": int(len(preds)), "acc": cap_acc, "majority_pred": int(vote)})

    if not win_gt:
        print("\nNo windows produced from any capture. Check MAC, channel, and that data frames were captured.")
        sys.exit(1)

    # 5 — aggregate metrics
    win_gt = np.asarray(win_gt)
    win_pred = np.asarray(win_pred)
    n_win = len(win_gt)

    top1 = float(np.mean(win_pred == win_gt))
    mf1 = macro_f1(win_gt, win_pred)

    # session-level majority vote
    sess_correct = sum(1 for s, ps in session_preds.items()
                       if Counter(ps).most_common(1)[0][0] == session_gt[s])
    sess_total = len(session_preds)
    sess_acc = sess_correct / sess_total if sess_total else 0.0

    # baselines
    chance = 1.0 / num_classes
    gt_counts = Counter(win_gt.tolist())
    majority_class_baseline = max(gt_counts.values()) / n_win  # always-predict-most-common-true-class

    # 6 — report
    print("\n" + "=" * 68)
    print("  RESULTS")
    print("=" * 68)
    print(f"  captures evaluated     : {sum(1 for c in per_capture if c['windows'])}")
    print(f"  windows                : {n_win}")
    print(f"  classes in ground truth: {len(gt_counts)} / {num_classes}")
    print("  " + "-" * 50)
    print(f"  window top-1 accuracy  : {top1*100:6.2f}%")
    print(f"  window macro-F1        : {mf1*100:6.2f}%")
    print(f"  session top-1 (vote)   : {sess_acc*100:6.2f}%   ({sess_correct}/{sess_total})")
    print("  " + "-" * 50)
    print(f"  chance baseline (1/N)  : {chance*100:6.2f}%")
    print(f"  majority-class baseline: {majority_class_baseline*100:6.2f}%")
    print("  " + "-" * 50)

    # interpretation
    ratio = top1 / chance if chance else float("inf")
    if top1 <= max(chance * 2, majority_class_baseline + 1e-9):
        verdict = ("AT/NEAR CHANCE — the synthetic-trained model does NOT transfer to real "
                   "captures (expected). This is the headline justification to re-haul: retrain "
                   "on real data with size/direction/timing-sequence features.")
    elif ratio < 10:
        verdict = ("ABOVE CHANCE but weak — some signal survives; investigate which features "
                   "(ablate the fabricated RF channels) before trusting it.")
    else:
        verdict = ("SUBSTANTIALLY ABOVE CHANCE — unexpected given the diagnosis; double-check "
                   "label mapping and that captures are truly one-service-per-window.")
    print(f"  VERDICT: {verdict}")
    print("=" * 68)

    # top confusions
    print("\n  Per-true-class summary:")
    print(f"  {'CSTNET':>8} {'win':>5} {'acc%':>6}  top-predicted (CSTNET:count)")
    for c in sorted(gt_counts):
        mask = win_gt == c
        preds_c = win_pred[mask]
        acc_c = float(np.mean(preds_c == c)) * 100
        top = Counter(preds_c.tolist()).most_common(3)
        top_str = ", ".join(f"{to_cstnet(p)}:{n}" for p, n in top)
        print(f"  {to_cstnet(c):>8} {int(mask.sum()):>5} {acc_c:>6.1f}  {top_str}")

    # 7 — JSON
    if args.out:
        report = {
            "checkpoint": str(ckpt), "in_channels": in_channels, "num_classes": num_classes,
            "windows": int(n_win), "window_top1": top1, "window_macro_f1": mf1,
            "session_top1": sess_acc, "chance_baseline": chance,
            "majority_class_baseline": majority_class_baseline,
            "per_capture": per_capture,
        }
        Path(args.out).write_text(json.dumps(report, indent=2))
        print(f"\n  JSON report → {args.out}")


if __name__ == "__main__":
    main()
