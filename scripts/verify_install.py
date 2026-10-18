#!/usr/bin/env python3
"""Exercise installed capture/build/train/inference entirely offline on this device.

Fixtures are synthetic protected-frame envelopes, not real encryption or an
accuracy benchmark. Real capture evaluation is reported separately.
"""
from __future__ import annotations

import argparse
import csv
import json
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'data/field/install-check')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    import numpy as np
    import torch
    from scapy.all import Dot11, Dot11QoS, RadioTap, Raw, wrpcap
    from wifi_app.dataset import build_field_dataset
    from wifi_app.training import (load_field_dataset, grouped_split_indices,
        train_logistic_baseline, train_tcn, save_bundle, export_tcn_onnx)
    from infer.field_inference import infer_capture, load_bundle
    torch.set_num_threads(2)
    torch.manual_seed(42)
    np.random.seed(42)
    started = time.monotonic()
    bssid, client = '02:00:00:00:00:01', '02:00:00:00:00:11'
    rows = []
    for mic in (8, 16):
        for label, size in [('fixture_small', 96), ('fixture_large', 900)]:
            for session in range(3):
                sid = f'synthetic-{mic}-{label}-{session}'
                pcap = args.out / f'{sid}.pcap'
                packets = []
                for index in range(96):
                    up = index % 2 == 0
                    packet = RadioTap() / Dot11(type=2, subtype=8,
                        FCfield=0x41 if up else 0x42,
                        addr1=bssid if up else client, addr2=client if up else bssid,
                        addr3='02:00:00:00:00:aa', SC=(index + 1) << 4) / Dot11QoS(TID=3) / Raw(
                            bytes([index + 1, 0, 0, 0x20, 0, 0, 0, 0]) + bytes([0xa5 ^ index]) * size + bytes(mic))
                    packet.time = 100 + index * 0.05
                    packets.append(packet)
                wrpcap(str(pcap), packets)
                rows.append(dict(pcap=pcap.name, bssid=bssid, client_mac=client,
                    label=label, session_id=sid, device_id='synthetic',
                    security='synthetic-ccmp-envelope' if mic == 8 else 'synthetic-gcmp-envelope'))
    manifest = args.out / 'manifest.csv'
    with manifest.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader();writer.writerows(rows)
    data = args.out / 'dataset.parquet'
    built = build_field_dataset(manifest, data, window_size=32, stride=32, min_frames=16)
    arrays = load_field_dataset(data)
    train, val = grouped_split_indices(arrays, folds=3)
    models = {}
    for kind in ('baseline', 'tcn'):
        if kind == 'baseline':
            bundle, report = train_logistic_baseline(arrays, train, val)
            dest = args.out / 'baseline.joblib'
        else:
            bundle, report = train_tcn(arrays, train, val, width=8, blocks=1,
                epochs=2, batch_size=8, patience=2, dropout=0, device='cpu', unknown_threshold=0)
            dest = args.out / 'tcn.pt'
        checkpoint, _ = save_bundle(bundle, report, dest)
        if kind == 'tcn':
            export_tcn_onnx(bundle, args.out / 'tcn.onnx')
        loaded = load_bundle(checkpoint)
        inference = infer_capture(args.out / rows[0]['pcap'], bssid, loaded, client_mac=client, device='cpu')
        if inference.get('status') != 'ok' or not inference.get('windows'):
            raise RuntimeError(f'{kind} inference failed: {inference}')
        (args.out / f'{kind}.inference.json').write_text(json.dumps(inference, indent=2))
        models[kind] = {'status': 'passed', 'windows': len(inference['windows']), 'validation': report['validation']}
    result = dict(status='passed', scope='offline installation smoke test; synthetic data, not field accuracy',
        host=platform.node(), machine=platform.machine(), python=platform.python_version(),
        torch=torch.__version__, device='cpu', samples=built['samples'], source_sessions=built['source_sessions'],
        models=models, elapsed_seconds=round(time.monotonic() - started, 2), timestamp=time.time())
    (args.out / 'verification.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
