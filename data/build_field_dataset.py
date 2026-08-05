#!/usr/bin/env python3
"""Build a real-capture, BSSID-scoped field dataset from a manifest.

Example:
    python data/build_field_dataset.py --manifest data/field_manifest.csv \
        --out data/field/dataset.parquet
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wifi_app.dataset import build_field_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a BSSID-scoped raw-802.11 field dataset")
    parser.add_argument("--manifest", required=True, help="CSV containing pcap,bssid,label and grouping metadata")
    parser.add_argument("--out", required=True, help="Output Parquet path")
    parser.add_argument("--window-size", type=int, default=64)
    parser.add_argument("--stride", type=int, default=32)
    parser.add_argument("--min-frames", type=int, default=16)
    parser.add_argument("--idle-timeout", type=float, default=15.0)
    parser.add_argument("--include-unprotected", action="store_true",
                        help="Include unprotected data frames (default: protected frames only)")
    parser.add_argument("--keep-retries", action="store_true",
                        help="Do not collapse immediately repeated retry frames")
    args = parser.parse_args()
    report = build_field_dataset(
        args.manifest,
        args.out,
        window_size=args.window_size,
        stride=args.stride,
        min_frames=args.min_frames,
        idle_timeout_seconds=args.idle_timeout,
        require_protected=not args.include_unprotected,
        deduplicate_retries=not args.keep_retries,
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
