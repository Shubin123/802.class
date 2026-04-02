#!/usr/bin/env python3
"""
Side-by-side comparison: training parquet features vs scapy-extracted features
for the SAME pcap. This reveals exactly which features differ.
"""
import sys, io, zipfile
from pathlib import Path
import numpy as np

try:
    from scapy.all import PcapReader, PcapNgReader, RadioTap, Dot11, conf
    conf.verb = 0
except ImportError:
    print("scapy required"); sys.exit(1)

SCRIPT_DIR = Path(__file__).parent.resolve()
DATA_ZIP   = SCRIPT_DIR / ".." / "data" / "dataset_output" / "dataset.parquet.zip"
CAPTURES   = SCRIPT_DIR / ".." / "data" / "dataset_output" / "captures"

def _open_pcap(pcap_path):
    path = str(pcap_path)
    try:
        return PcapNgReader(path)
    except Exception:
        return PcapReader(path)

def extract_from_pcap(pcap_path):
    """Extract features from pcap using scapy (same method as inference.py)."""
    records = []
    prev_ts = None
    for pkt in _open_pcap(pcap_path):
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        if d.type != 2 or d.subtype != 0:
            continue
        
        ts = float(pkt.time)
        iat = (ts - prev_ts) if prev_ts is not None else 0.0
        prev_ts = ts
        frame_len = len(pkt)
        seq_num = (d.SC >> 4) if d.SC else 0
        duration = d.ID if d.ID else 0
        
        signal_dbm = -30.0  # placeholder
        data_rate = 0.0
        mcs_index = 0
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            try:
                if rt.dBm_AntSignal is not None: signal_dbm = float(rt.dBm_AntSignal)
            except: pass
            try:
                if rt.Rate is not None: data_rate = float(rt.Rate)
            except: pass
            try:
                if rt.MCS_index is not None: mcs_index = int(rt.MCS_index)
            except: pass
        
        records.append({
            'iat': iat,
            'frame_len': frame_len,
            'seq_num': seq_num,
            'duration': duration,
            'signal_dbm': signal_dbm,
            'data_rate': data_rate,
            'mcs_index': mcs_index,
            'log_iat': np.log1p(iat),
            'frame_len_kb': frame_len / 1024.0,
        })
    return records

def main():
    import pandas as pd
    
    label = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    pcap_path = CAPTURES / f"{label}.pcap"
    
    print(f"═══ Comparing label {label} ═══")
    print(f"Pcap: {pcap_path}")
    
    # 1. Load training parquet
    print("\n[1] Loading training parquet …")
    if DATA_ZIP.exists():
        zf = zipfile.ZipFile(DATA_ZIP)
        with zf.open(zf.namelist()[0]) as f:
            df = pd.read_parquet(io.BytesIO(f.read()))
    else:
        df = pd.read_parquet(SCRIPT_DIR / ".." / "data" / "dataset_output" / "dataset.parquet")
    
    # Get rows for this label (before augmentation remap)
    unique_labels = sorted(df['label'].unique())
    label_map = {orig: i for i, orig in enumerate(unique_labels)}
    
    # The parquet uses string labels
    label_str = str(label)
    if label_str in df['label'].values:
        parquet_rows = df[df['label'] == label_str]
    else:
        parquet_rows = df[df['label'] == label]
    
    print(f"    Parquet rows for label {label}: {len(parquet_rows)}")
    
    # 2. Extract from pcap
    print("\n[2] Extracting from pcap with scapy …")
    scapy_rows = extract_from_pcap(pcap_path)
    print(f"    Scapy frames: {len(scapy_rows)}")
    
    # 3. Compare feature columns
    compare_cols = ['iat', 'frame_len', 'seq_num', 'duration', 
                    'signal_dbm', 'data_rate', 'mcs_index', 'log_iat', 'frame_len_kb']
    
    print(f"\n[3] Feature comparison (first 10 frames):")
    print(f"    {'Feature':>15} | {'Parquet':>12} | {'Scapy':>12} | {'Delta':>12}")
    print(f"    {'-'*60}")
    
    n_compare = min(10, len(parquet_rows), len(scapy_rows))
    parquet_vals = parquet_rows.iloc[:n_compare]
    
    for i in range(n_compare):
        print(f"\n    Frame {i}:")
        for col in compare_cols:
            if col in parquet_vals.columns:
                pv = float(parquet_vals.iloc[i][col])
            else:
                pv = float('nan')
            sv = scapy_rows[i][col]
            delta = sv - pv if np.isfinite(pv) else float('nan')
            flag = " ◀◀◀" if abs(delta) > 0.01 and np.isfinite(delta) else ""
            print(f"    {col:>15} | {pv:>12.4f} | {sv:>12.4f} | {delta:>12.4f}{flag}")
    
    # 4. Statistical comparison
    print(f"\n[4] Statistical comparison (all frames):")
    print(f"    {'Feature':>15} | {'Parquet mean':>12} {'std':>10} | {'Scapy mean':>12} {'std':>10} | {'Δ mean':>10}")
    print(f"    {'-'*80}")
    
    for col in compare_cols:
        if col in parquet_vals.columns:
            pcol = parquet_rows[col].values.astype(float)
        else:
            continue
        scol = np.array([r[col] for r in scapy_rows], dtype=float)
        
        # Truncate to same length
        n = min(len(pcol), len(scol))
        pcol = pcol[:n]
        scol = scol[:n]
        
        dm = scol.mean() - pcol.mean()
        flag = " ◀◀◀" if abs(dm) > 0.5 else ""
        print(f"    {col:>15} | {pcol.mean():>12.4f} {pcol.std():>10.4f} | "
              f"{scol.mean():>12.4f} {scol.std():>10.4f} | {dm:>10.4f}{flag}")
    
    # 5. Unique values comparison
    print(f"\n[5] Unique values per feature:")
    for col in compare_cols:
        if col in parquet_rows.columns:
            p_uniq = parquet_rows[col].nunique()
        else:
            p_uniq = '?'
        s_vals = [r[col] for r in scapy_rows]
        s_uniq = len(set(s_vals))
        print(f"    {col:>15}: parquet={p_uniq}, scapy={s_uniq}")

if __name__ == "__main__":
    main()
