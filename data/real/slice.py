#!/usr/bin/env python3
"""
slice.py — runs ON THE MAC after capture. Cuts a continuous monitor-mode pcap into
per-service pcaps using the DUT's dut_run.csv (timestamp windows) + the DUT Wi-Fi MAC,
writes sessions/*.pcapng + manifest.csv, then (optionally) runs eval_real.py.

The Mac and DUT clocks just need to be NTP-synced; windows have guard bands.

    python slice.py --pcap capture.pcapng --schedule dut_run.csv --mac AA:BB:CC:DD:EE:FF
    python slice.py --pcap capture.pcapng --schedule dut_run.csv --mac ... --eval
"""
import argparse
import csv
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent.resolve()
TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="continuous monitor capture")
    ap.add_argument("--schedule", default=str(HERE / "dut_run.csv"))
    ap.add_argument("--mac", required=True, help="DUT Wi-Fi on-air MAC")
    ap.add_argument("--out-dir", default=str(HERE / "sessions"))
    ap.add_argument("--manifest", default=str(HERE / "manifest.csv"))
    ap.add_argument("--guard", type=float, default=1.0, help="seconds trimmed off each window edge")
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--checkpoint", default=str(HERE / ".." / ".." / "train" / "checkpoints" / "best_resnet.pt.600epoch"))
    args = ap.parse_args()

    pcap = Path(args.pcap)
    if not pcap.exists():
        sys.exit(f"pcap not found: {pcap}")
    mac = args.mac.lower().replace("-", ":")
    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader(open(args.schedule)))
    print(f"slicing {pcap.name} into {len(rows)} windows for MAC {mac}")

    manifest = []
    for r in rows:
        label, name, sess = r["label"], r["name"], r["session"]
        start = float(r["start_epoch"]) + args.guard
        end = float(r["end_epoch"]) - args.guard
        out = out_dir / f"{label}__{name}__{sess}.pcapng"
        flt = (f"frame.time_epoch >= {start} && frame.time_epoch <= {end} "
               f"&& wlan.fc.type == 2 && wlan.addr == {mac}")
        subprocess.run([TSHARK, "-r", str(pcap), "-Y", flt, "-w", str(out)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        n = 0
        if out.exists():
            c = subprocess.run([TSHARK, "-r", str(out), "-T", "fields", "-e", "frame.number"],
                               capture_output=True, text=True)
            n = sum(1 for l in c.stdout.splitlines() if l.strip())
        flag = "  <- LOW (wrong channel/MAC, or traffic went over Ethernet)" if n < 128 else ""
        print(f"  {name:12} {sess}  label {label:>3}  {n:5d} data frames{flag}")
        manifest.append({"pcap": f"sessions/{out.name}", "mac": mac, "label": label, "session": sess})

    with open(args.manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["pcap", "mac", "label", "session"])
        w.writeheader(); w.writerows(manifest)
    print(f"\nmanifest: {args.manifest}")

    if args.eval:
        print("\nrunning eval_real.py …\n")
        subprocess.run([sys.executable, str(HERE / ".." / ".." / "infer" / "eval_real.py"),
                        "--manifest", args.manifest, "--checkpoint", args.checkpoint])


if __name__ == "__main__":
    main()
