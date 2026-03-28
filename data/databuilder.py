"""
build_dataset.py
Extracts raw encrypted payload bytes from per-label pcap files and writes a parquet.

Usage:
    python build_dataset.py --pcap-dir ../data/pcaps --out ../data/dataset_output/dataset.parquet

Expects pcap files named by label, e.g. youtube.pcap, netflix.pcap, etc.
"""

import argparse
import subprocess
import os
import numpy as np
import pandas as pd
from pathlib import Path

PAYLOAD_BYTES = 256  # how many bytes to take from each frame (zero-padded if shorter)


def extract_pcap(pcap_path: Path, label: str) -> pd.DataFrame:
    cmd = [
        "tshark", "-r", str(pcap_path),
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.len",
        "-e", "data.data",
        "-E", "header=n",
        "-E", "separator=,",
        "-E", "occurrence=f"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    rows = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(",", 2)
        if len(parts) < 3:
            continue
        frame_num, frame_len, hex_data = parts
        hex_data = hex_data.replace(":", "").strip()
        if not hex_data:
            continue
        try:
            raw = bytes.fromhex(hex_data)
        except ValueError:
            continue
        # Take first PAYLOAD_BYTES, zero-pad if shorter
        arr = np.zeros(PAYLOAD_BYTES, dtype=np.uint8)
        arr[:min(len(raw), PAYLOAD_BYTES)] = list(raw[:PAYLOAD_BYTES])
        rows.append({
            "label":     label,
            "frame_len": int(frame_len) if frame_len.isdigit() else 0,
            "payload":   arr.tolist()
        })
    print(f"  {label}: {len(rows)} frames")
    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap-dir", type=str, required=True)
    parser.add_argument("--out",      type=str, default="../data/dataset_output/dataset.parquet")
    args = parser.parse_args()

    pcap_dir = Path(args.pcap_dir)
    pcaps    = sorted(pcap_dir.glob("*.pcap")) + sorted(pcap_dir.glob("*.pcapng"))
    if not pcaps:
        print(f"No pcap files found in {pcap_dir}")
        return

    print(f"Found {len(pcaps)} pcap files")
    frames = []
    for pcap in pcaps:
        label = pcap.stem  # filename without extension = label
        df    = extract_pcap(pcap, label)
        if len(df):
            frames.append(df)

    if not frames:
        print("No data extracted. Check tshark is installed and pcaps have data.data fields.")
        return

    df = pd.concat(frames, ignore_index=True)
    print(f"\nTotal frames: {len(df):,} across {df['label'].nunique()} classes")
    print(df['label'].value_counts())

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.out, index=False)
    print(f"\nSaved to {args.out}")


if __name__ == "__main__":
    main()

# run with python databuilder.py --pcap-dir ../dataset_output/captures --out ./