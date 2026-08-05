#!/usr/bin/env python3
"""Capture a channel-locked raw monitor-mode PCAP for the field pipeline.

This wrapper intentionally does not generate traffic.  The field device is a
passive observer; use a separate DUT/control path for authorized labeled data
collection.  Configure monitor mode/channel yourself when the OS/driver does
not let dumpcap do so reliably.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Record raw 802.11 monitor-mode traffic with dumpcap")
    parser.add_argument("--interface", required=True, help="Dedicated monitor-capable Wi-Fi interface")
    parser.add_argument("--out", required=True, help="Output .pcapng path")
    parser.add_argument("--duration", type=int, required=True, help="Capture duration in seconds")
    parser.add_argument("--bssid", default=None, help="Optional selected BSSID recorded as sidecar metadata")
    parser.add_argument("--channel-frequency", type=int, default=None,
                        help="MHz frequency to request from dumpcap; platform/driver support varies")
    parser.add_argument("--set-channel", action="store_true",
                        help="Pass the requested frequency to dumpcap (-k); opt in only after hardware validation")
    parser.add_argument("--no-monitor", action="store_true",
                        help="Do not pass -I; use when interface was already placed in monitor mode manually")
    parser.add_argument("--snaplen", type=int, default=0, help="Snapshot length; 0 keeps full frames")
    parser.add_argument("--dumpcap", default="dumpcap", help="dumpcap executable")
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("--duration must be positive")
    if args.set_channel and args.channel_frequency is None:
        parser.error("--set-channel requires --channel-frequency")
    if not Path(args.dumpcap).exists() and not shutil.which(args.dumpcap):
        parser.error(f"dumpcap not found: {args.dumpcap}")

    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    command = [args.dumpcap, "-i", args.interface, "-w", str(out), "-a", f"duration:{args.duration}", "-q"]
    if not args.no_monitor:
        command.append("-I")
    if args.snaplen > 0:
        command.extend(["-s", str(args.snaplen)])
    if args.set_channel:
        command.extend(["-k", str(args.channel_frequency)])
    started = time.time()
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=args.duration + 30)
    except subprocess.TimeoutExpired:
        parser.error("dumpcap did not stop after the requested duration")
    if completed.returncode != 0:
        sys.stderr.write(completed.stderr)
        parser.error(f"dumpcap exited with code {completed.returncode}")
    sidecar = out.with_suffix(out.suffix + ".capture.json")
    sidecar.write_text(json.dumps({
        "captured_at_epoch": started,
        "duration_requested_seconds": args.duration,
        "interface": args.interface,
        "bssid_requested": args.bssid,
        "channel_frequency_requested_mhz": args.channel_frequency if args.set_channel else None,
        "monitor_requested_to_dumpcap": not args.no_monitor,
        "snaplen": args.snaplen,
        "command": command,
        "note": "Verify BSSID/channel/radiotap/frame counts with field_inference.py before using as training data.",
    }, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"pcap": str(out), "metadata": str(sidecar), "bytes": out.stat().st_size if out.exists() else 0}, indent=2))


if __name__ == "__main__":
    main()
