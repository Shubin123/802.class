#!/usr/bin/env python3
"""Train and evaluate real field captures on this machine with held-out sessions."""
import argparse
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data', type=Path, default=ROOT / 'data/field/cm4/dataset.parquet')
    p.add_argument('--models', type=Path, default=ROOT / 'models')
    p.add_argument('--epochs', type=int, default=20)
    args = p.parse_args()
    import torch
    from wifi_app.training import (load_field_dataset, grouped_split_indices,
        train_logistic_baseline, train_tcn, save_bundle, export_tcn_onnx)
    from infer.field_inference import infer_capture, load_bundle
    torch.set_num_threads(2)
    torch.manual_seed(42)
    arrays = load_field_dataset(args.data)
    train, val = grouped_split_indices(arrays, folds=3)
    report = {'host': platform.node(), 'machine': platform.machine(),
        'samples': len(arrays.y), 'source_sessions': len(set(arrays.groups)),
        'train_groups': sorted(set(arrays.groups[train])),
        'validation_groups': sorted(set(arrays.groups[val])),
        'scope': 'Small scripted URL-fetch trial on one DUT/AP; not native-app accuracy.',
        'wpa3_status': 'Not tested: SAE test AP required', 'models': {}}
    args.models.mkdir(parents=True, exist_ok=True)
    for kind in ('baseline', 'tcn'):
        if kind == 'baseline':
            bundle, metrics = train_logistic_baseline(arrays, train, val)
            path = args.models / 'cm4_baseline.joblib'
        else:
            bundle, metrics = train_tcn(arrays, train, val, width=16, blocks=2,
                epochs=args.epochs, batch_size=32, patience=8, device='cpu', unknown_threshold=0.6)
            path = args.models / 'cm4_tcn.pt'
        save_bundle(bundle, metrics, path)
        if kind == 'tcn':
            export_tcn_onnx(bundle, args.models / 'cm4_tcn.onnx')
        report['models'][kind] = metrics
        heldout = arrays.frame.iloc[int(val[0])]
        result = infer_capture(heldout['pcap'], heldout['bssid'], load_bundle(path),
            client_mac=heldout['client_mac'], device='cpu')
        if result.get('status') != 'ok':
            raise RuntimeError(f'{kind}: no usable held-out inference')
        (args.data.parent / f'{kind}.heldout-inference.json').write_text(json.dumps(result, indent=2))
        if kind == 'tcn':
            (args.data.parent / 'independent-inference.json').write_text(json.dumps(result, indent=2))
    modes = set(arrays.frame.get('security', []))
    report['observed_security_modes'] = sorted(modes)
    report['wpa2_status'] = 'Protected capture + grouped inference passed' if 'wpa2' in modes else 'Not tested'
    if 'wpa3' in modes:
        # Mixed-mode aggregate scores alone are not per-mode validation.
        report['wpa3_status'] = 'Captured; separate held-out WPA3 evaluation still required'
    (args.data.parent / 'evaluation.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
