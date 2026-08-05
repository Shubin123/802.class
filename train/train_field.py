#!/usr/bin/env python3
"""Grouped training for the real raw-802.11 field dataset.

Unlike the legacy trainer, this loader splits whole manifest sessions before
normalization and never mixes their overlapping windows across partitions.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wifi_app.training import (
    export_tcn_onnx,
    grouped_split_indices,
    load_field_dataset,
    save_bundle,
    train_logistic_baseline,
    train_tcn,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a grouped real-capture 802.11 field model")
    parser.add_argument("--data", required=True, help="Parquet from data/build_field_dataset.py")
    parser.add_argument("--out", required=True, help="Checkpoint (.pt for TCN, .joblib for baseline)")
    parser.add_argument("--model", choices=("baseline", "tcn"), default="tcn")
    parser.add_argument("--group-column", default="source_session_id")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--fold-index", type=int, default=0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--learning-rate", type=float, default=3e-4)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--width", type=int, default=48)
    parser.add_argument("--blocks", type=int, default=4)
    parser.add_argument("--dropout", type=float, default=0.10)
    parser.add_argument("--unknown-threshold", type=float, default=0.60)
    parser.add_argument("--device", default=None, help="Torch device, e.g. cuda or cpu")
    parser.add_argument("--export-onnx", default=None, help="Optional static-shape ONNX export path for a TCN")
    args = parser.parse_args()

    arrays = load_field_dataset(args.data, group_column=args.group_column)
    train_idx, val_idx = grouped_split_indices(
        arrays, folds=args.folds, fold_index=args.fold_index, random_state=args.seed
    )
    if args.model == "baseline":
        bundle, report = train_logistic_baseline(arrays, train_idx, val_idx, random_state=args.seed)
    else:
        bundle, report = train_tcn(
            arrays, train_idx, val_idx,
            width=args.width,
            blocks=args.blocks,
            dropout=args.dropout,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            weight_decay=args.weight_decay,
            patience=args.patience,
            unknown_threshold=args.unknown_threshold,
            device=args.device,
        )
    report.update({
        "data": str(Path(args.data).resolve()),
        "group_column": args.group_column,
        "train_groups": int(len(set(arrays.groups[train_idx]))),
        "validation_groups": int(len(set(arrays.groups[val_idx]))),
        "labels": list(arrays.labels),
        "window_size": arrays.window_size,
    })
    output, report_path = save_bundle(bundle, report, args.out)
    if args.export_onnx:
        if args.model != "tcn":
            parser.error("--export-onnx is only valid with --model tcn")
        export_tcn_onnx(bundle, args.export_onnx)
        report["onnx"] = str(Path(args.export_onnx).resolve())
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"checkpoint": str(output), "report": str(report_path), **report["validation"]}, indent=2))


if __name__ == "__main__":
    main()
