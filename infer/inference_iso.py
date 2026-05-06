#!/usr/bin/env python3
"""
802.11 Encrypted Traffic Classifier — Inference (with TLS OOD Gate)
====================================================================
Adds one-class OOD filtering (Isolation Forest) before classification
to remove non-TLS traffic (DNS, QUIC, noise, etc.).
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
import joblib

# ─────────────────────────────────────────────────────────────
# Model import
# ─────────────────────────────────────────────────────────────
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "train", str(Path(__file__).parent.resolve() / ".." / "train" / "train.py"))
_train = importlib.util.module_from_spec(_spec)
sys.modules["train"] = _train
_spec.loader.exec_module(_train)

TrafficResNet = _train.TrafficResNet

# ─────────────────────────────────────────────────────────────
# Scapy
# ─────────────────────────────────────────────────────────────
try:
    from scapy.all import PcapReader, PcapNgReader, Dot11
    from scapy.all import RadioTap
except ImportError:
    print("pip install scapy")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
WINDOW_SIZE = 128
PAYLOAD_BYTES = 256

SCRIPT_DIR = Path(__file__).parent.resolve()
CHECKPOINT_DIR = SCRIPT_DIR / ".." / "train" / "checkpoints"

OOD_PATH = CHECKPOINT_DIR / "tls_ood_iforest.pkl"

LABELS = sorted([str(i) for i in range(120)])

# ─────────────────────────────────────────────────────────────
# PCAP
# ─────────────────────────────────────────────────────────────
def open_pcap(path):
    try:
        return PcapNgReader(str(path))
    except:
        return PcapReader(str(path))

def find_captures(d=None):
    d = Path(d) if d else SCRIPT_DIR
    return sorted(d.glob("*.pcap")) + sorted(d.glob("*.pcapng"))

# ─────────────────────────────────────────────────────────────
# MAC scan
# ─────────────────────────────────────────────────────────────
def scan_macs(pcap_path):
    from scapy.all import RawPcapReader, RawPcapNgReader
    import struct

    mac_counts = Counter()
    total = matched = 0

    try:
        reader = RawPcapNgReader(str(pcap_path))
    except:
        reader = RawPcapReader(str(pcap_path))

    for raw, _ in reader:
        total += 1
        data = bytes(raw)

        if len(data) < 10:
            continue

        rt_len = struct.unpack_from("<H", data, 2)[0]
        dot11 = rt_len

        if len(data) < dot11 + 24:
            continue

        fc = struct.unpack_from("<H", data, dot11)[0]
        t = (fc >> 2) & 3
        st = (fc >> 4) & 15

        if t != 2 or st != 0:
            continue

        matched += 1

        mac = data[dot11 + 10:dot11 + 16]
        mac = ":".join(f"{b:02x}" for b in mac)

        if mac != "ff:ff:ff:ff:ff:ff":
            mac_counts[mac] += 1

    return dict(mac_counts)

# ─────────────────────────────────────────────────────────────
# Feature extraction (payload)
# ─────────────────────────────────────────────────────────────
def extract_payload(pcap, mac, size=PAYLOAD_BYTES):
    rows = []
    mac = mac.lower()

    for pkt in open_pcap(pcap):
        if not pkt.haslayer(Dot11):
            continue

        d = pkt[Dot11]
        if d.type != 2 or d.subtype != 0:
            continue

        addrs = {(a or "").lower() for a in (d.addr1, d.addr2, d.addr3)}
        if mac not in addrs:
            continue

        body = bytes(d.payload) if d.payload else b""
        arr = np.zeros(size, dtype=np.uint8)
        arr[:min(len(body), size)] = np.frombuffer(body[:size], dtype=np.uint8)

        rows.append(arr)

    return np.array(rows, dtype=np.float32) if rows else np.zeros((0, size))

# ─────────────────────────────────────────────────────────────
# Model loading
# ─────────────────────────────────────────────────────────────
def load_model(path=None):
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    if path is None:
        path = next(CHECKPOINT_DIR.glob("best_*.pt"))

    sd = torch.load(path, map_location=dev)

    in_ch = sd["stem.0.weight"].shape[1]
    ncls = sd["fc.weight"].shape[0]

    model = TrafficResNet(num_classes=ncls, in_channels=in_ch).to(dev)
    model.load_state_dict(sd)
    model.eval()

    print(f"[model] in={in_ch} classes={ncls}")
    return model, dev, in_ch, ncls

# ─────────────────────────────────────────────────────────────
# OOD model
# ─────────────────────────────────────────────────────────────
def load_ood():
    if not OOD_PATH.exists():
        print("[ood] WARNING: no OOD model found (all traffic passes)")
        return None
    return joblib.load(OOD_PATH)

# ─────────────────────────────────────────────────────────────
# Inference with OOD gate
# ─────────────────────────────────────────────────────────────
def infer(model, dev, feats, ood, in_ch):
    if len(feats) == 0:
        return np.array([]), np.array([]), np.array([])

    nw = len(feats) // WINDOW_SIZE
    if nw == 0:
        pad = np.zeros((WINDOW_SIZE, in_ch))
        pad[:len(feats)] = feats
        feats = pad
        nw = 1
    else:
        feats = feats[:nw * WINDOW_SIZE]

    w = feats.reshape(nw, WINDOW_SIZE, in_ch).transpose(0, 2, 1)

    # ── OOD gating ─────────────────────────────
    if ood is not None:
        w_flat = w.mean(axis=2)
        keep = ood.predict(w_flat) == 1
    else:
        keep = np.ones(nw, dtype=bool)

    preds = np.full(nw, -1)
    confs = np.zeros((nw, model.fc.out_features))

    with torch.no_grad():
        logits = model(torch.from_numpy(w).float().to(dev))
        probs = torch.softmax(logits, 1).cpu().numpy()

    preds[keep] = probs[keep].argmax(1)
    confs[keep] = probs[keep]

    return preds, confs, keep

# ─────────────────────────────────────────────────────────────
# MAC display
# ─────────────────────────────────────────────────────────────
def show_macs(macs):
    items = sorted(macs.items(), key=lambda x: -x[1])
    for i,(m,c) in enumerate(items):
        print(f"{i}: {m} ({c})")
    return items

# ─────────────────────────────────────────────────────────────
# Results
# ─────────────────────────────────────────────────────────────
def show(preds, confs):
    valid = preds[preds != -1]
    print(f"\nValid TLS windows: {len(valid)}/{len(preds)}")

    for i,p in enumerate(preds):
        if p == -1:
            print(f"{i}: REJECTED (non-TLS)")
        else:
            print(f"{i}: class {p} conf={confs[i][p]:.2f}")

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap")
    ap.add_argument("--mac")
    ap.add_argument("--checkpoint")
    args = ap.parse_args()

    model, dev, in_ch, _ = load_model(args.checkpoint)
    ood = load_ood()

    pcap = Path(args.pcap) if args.pcap else find_captures()[0]

    macs = scan_macs(pcap)
    items = show_macs(macs)

    mac = args.mac if args.mac else items[0][0]

    feats = extract_payload(pcap, mac, in_ch)

    preds, confs, mask = infer(model, dev, feats, ood, in_ch)

    show(preds, confs)

if __name__ == "__main__":
    main()
