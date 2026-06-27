#!/usr/bin/env python3
"""
dut.py — runs ON THE WINDOWS DUT (the traffic source). A NORMAL Wi-Fi client; it
never goes into monitor mode. The Mac sniffs its frames over the air.

The DUT has both Wi-Fi and Ethernet, so traffic is FORCED out Wi-Fi by binding curl
to the Wi-Fi adapter's IP (`curl --interface <wifi-ip>`) — otherwise it would egress
Ethernet and the capture would be empty.

Two steps:
    python dut.py --info     # print Wi-Fi iface / IP / MAC / channel — paste to the Mac
    python dut.py            # run the schedule: load each service over Wi-Fi, log times

The run writes data/real/dut_run.csv (label,name,session,start_epoch,end_epoch). The
Mac captures continuously during the run, then slices by those timestamps + the Wi-Fi
MAC. Clocks just need to be NTP-synced (Windows + macOS default), since windows are
tens of seconds with guard bands.

Stdlib only. Needs Python 3 and curl (built into Windows 10+/macOS/Linux).
"""
import argparse
import csv
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent.resolve()
IS_WIN = platform.system() == "Windows"
NULLDEV = "NUL" if IS_WIN else "/dev/null"


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except Exception as e:
        return f"(failed: {e})"


def chan_to_freq(ch):
    ch = int(ch)
    if ch == 14:
        return 2484
    if ch <= 14:
        return 2407 + 5 * ch
    return 5000 + 5 * ch


def wifi_info():
    """Return dict(iface, ip, mac, ssid, channel, freq) + raw text. Best-effort per OS."""
    info = {"iface": None, "ip": None, "mac": None, "ssid": None, "channel": None, "freq": None}
    raw = ""
    if IS_WIN:
        ns = _run(["netsh", "wlan", "show", "interfaces"])
        raw += "=== netsh wlan show interfaces ===\n" + ns + "\n"
        def grab(key):
            m = re.search(rf"^\s*{key}\s*:\s*(.+?)\s*$", ns, re.MULTILINE | re.IGNORECASE)
            return m.group(1).strip() if m else None
        info["iface"] = grab("Name")
        info["ssid"] = grab("SSID")
        info["channel"] = grab("Channel")
        info["mac"] = grab("Physical address")
        if info["channel"] and info["channel"].isdigit():
            info["freq"] = chan_to_freq(info["channel"])
        if info["iface"]:
            ps = _run(["powershell", "-NoProfile", "-Command",
                       f"(Get-NetIPAddress -InterfaceAlias '{info['iface']}' -AddressFamily IPv4"
                       f" -ErrorAction SilentlyContinue).IPAddress"])
            ip = ps.strip().splitlines()[0].strip() if ps.strip() else None
            info["ip"] = ip or info["ip"]
            if not info["mac"]:
                psm = _run(["powershell", "-NoProfile", "-Command",
                            f"(Get-NetAdapter -Name '{info['iface']}').MacAddress"])
                info["mac"] = psm.strip().splitlines()[0].strip() if psm.strip() else None
            raw += "=== powershell ip/mac ===\n" + ps + "\n"
    elif platform.system() == "Darwin":
        raw += _run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"])
        info["iface"] = "en0"
        info["ip"] = (_run(["ipconfig", "getifaddr", "en0"]) or "").strip() or None
    else:  # Linux (for local testing)
        w = _run(["bash", "-lc", "for n in /sys/class/net/*/wireless; do basename $(dirname $n); done | head -1"]).strip()
        info["iface"] = w or None
        if w:
            info["mac"] = _run(["bash", "-lc", f"cat /sys/class/net/{w}/address"]).strip() or None
            link = _run(["bash", "-lc", f"iw dev {w} link"]); raw += link
            m = re.search(r"freq:\s*(\d+)", link)
            if m:
                info["freq"] = int(m.group(1))
            info["ip"] = _run(["bash", "-lc", f"ip -o -4 addr show {w} | awk '{{print $4}}' | cut -d/ -f1"]).strip() or None
    if info["mac"]:
        info["mac"] = info["mac"].lower().replace("-", ":")
    return info, raw


def cmd_info():
    info, raw = wifi_info()
    print("---- paste these four lines to the Mac side ----")
    print(f"IFACE   = {info['iface']}")
    print(f"WIFI_IP = {info['ip']}")
    print(f"WIFI_MAC= {info['mac']}")
    print(f"CHANNEL = {info['channel']}   FREQ = {info['freq']}   SSID = {info['ssid']}")
    print("------------------------------------------------")
    if not (info["ip"] and info["mac"] and info["freq"]):
        print("\n[!] Some fields are blank — paste the raw output below and I'll extract them:\n")
        print(raw)


def fetch_once(url, wifi_ip):
    cmd = ["curl", "-s", "-m", "10", "-o", NULLDEV]
    if wifi_ip:
        cmd += ["--interface", wifi_ip]   # bind source -> egress Wi-Fi
    cmd.append(url)
    subprocess.run(cmd)


def cmd_run(args):
    info, _ = wifi_info()
    wifi_ip = args.wifi_ip or info["ip"]
    print(f"DUT run: iface={info['iface']} wifi_ip={wifi_ip} mac={info['mac']} "
          f"channel={info['channel']} freq={info['freq']}")
    if not wifi_ip:
        print("[!] No Wi-Fi IP found; traffic may egress Ethernet. Pass --wifi-ip <addr>.")
    services = list(csv.DictReader(open(args.services)))
    print(f"{len(services)} services x {args.sessions} sessions, {args.duration}s each. "
          f"Keep the Mac capturing for the whole run.\n")

    rows = []
    for s in range(1, args.sessions + 1):
        for svc in services:
            label, name, url = svc["label"].strip(), svc["name"].strip(), svc["url"].strip()
            time.sleep(args.guard)
            start = time.time()
            end_at = start + args.duration
            n = 0
            while time.time() < end_at:
                fetch_once(url, wifi_ip)
                n += 1
            end = time.time()
            rows.append({"label": label, "name": name, "session": f"s{s}",
                         "start_epoch": f"{start:.3f}", "end_epoch": f"{end:.3f}"})
            print(f"  s{s} {name:12} label {label:>3}  {n:4d} reqs  "
                  f"[{start:.1f} .. {end:.1f}]")
            time.sleep(args.idle)

    out = Path(args.out)
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["label", "name", "session", "start_epoch", "end_epoch"])
        w.writeheader(); w.writerows(rows)
    print(f"\nwrote {out}  ({len(rows)} windows)")
    print("Paste the schedule above (or send dut_run.csv) to the Mac side, plus the IFACE/MAC/CHANNEL.")


def main():
    ap = argparse.ArgumentParser(description="Windows DUT traffic generator")
    ap.add_argument("--info", action="store_true", help="just print Wi-Fi iface/ip/mac/channel")
    ap.add_argument("--services", default=str(HERE / "services.csv"))
    ap.add_argument("--out", default=str(HERE / "dut_run.csv"))
    ap.add_argument("--sessions", type=int, default=2)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--guard", type=float, default=2.0)
    ap.add_argument("--idle", type=float, default=5.0)
    ap.add_argument("--wifi-ip", default=None, help="override the Wi-Fi source IP for curl")
    args = ap.parse_args()
    if args.info:
        cmd_info()
    else:
        cmd_run(args)


if __name__ == "__main__":
    main()
