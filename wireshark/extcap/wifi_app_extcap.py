#!/usr/bin/env python3
"""Wireshark Extcap Capture Plugin for the 802.11 Raw Application Classifier.

Exposes a custom capture interface in Wireshark's capture list:
  "802.11 Application Classifier Live Capture"

Supports:
  1. Live monitor-mode capture on selected channel (via dumpcap / macos-monitor)
  2. Direct PCAP replay mode for demo, testing, and offline audits
  3. Seamless integration with the wifi_app_classifier.lua postdissector
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

EXTCAP_VERSION = "1.0.0"
INTERFACE_NAME = "wifi_app_live"
INTERFACE_DISPLAY = "802.11 Application Classifier Live Capture"
DLT_IEEE802_11_RADIO = 127


def extcap_interfaces() -> None:
    print(f"extcap {{version={EXTCAP_VERSION}}}{{help=https://github.com/Shubin123/802.class}}")
    print(f"interface {{value={INTERFACE_NAME}}}{{display={INTERFACE_DISPLAY}}}")


def extcap_dlts(interface: str) -> None:
    if interface == INTERFACE_NAME:
        print(f"dlt {{number={DLT_IEEE802_11_RADIO}}}{{name=IEEE802_11_RADIO}}{{display=802.11 plus radiotap header}}")


def extcap_config(interface: str) -> None:
    if interface != INTERFACE_NAME:
        return
    print("arg {number=0}{call=--iface}{display=Capture Interface}{type=string}{default=en0}{tooltip=Dedicated monitor radio interface}")
    print("arg {number=1}{call=--freq}{display=Channel Frequency (MHz)}{type=unsigned}{default=2412}{tooltip=Target channel frequency in MHz (e.g. 2412, 5220, 5805)}")
    print("arg {number=2}{call=--bssid}{display=Target AP BSSID}{type=string}{default=02:00:00:00:00:01}{tooltip=Radio MAC of the target access point}")
    print("arg {number=3}{call=--model}{display=Classification Engine}{type=selector}{tooltip=Active inference model for session tagging}")
    print("value {arg=3}{value=tcn}{display=Compact Temporal Convolutional Network (TCN)}{default=true}")
    print("value {arg=3}{value=baseline}{display=Logistic Aggregate Baseline}")
    print("arg {number=4}{call=--replay-pcap}{display=Replay Capture File}{type=fileselect}{tooltip=Optional: Stream existing capture for live inspection/demo}")


def capture_stream(fifo: str, iface: str, freq: int, bssid: str, replay_pcap: str | None) -> None:
    """Stream 802.11 frames to Wireshark's FIFO."""
    fifo_path = Path(fifo)

    # Replay existing capture if requested
    if replay_pcap and Path(replay_pcap).exists():
        src = Path(replay_pcap)
        with open(src, "rb") as f_in, open(fifo_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out, length=65536)
        return

    # Live capture mode via dumpcap
    dumpcap = shutil.which("dumpcap") or "/opt/homebrew/bin/dumpcap"
    if not os.path.exists(dumpcap):
        sys.exit(f"dumpcap not found: {dumpcap}")

    cmd = [dumpcap, "-i", iface, "-w", "-", "-q", "-I"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        with open(fifo_path, "wb") as f_out:
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                f_out.write(chunk)
                f_out.flush()
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    finally:
        if "proc" in locals() and proc.poll() is None:
            proc.terminate()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--extcap-interfaces", action="store_true")
    parser.add_argument("--extcap-dlts", action="store_true")
    parser.add_argument("--extcap-config", action="store_true")
    parser.add_argument("--extcap-interface", default=INTERFACE_NAME)
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--fifo", default="")
    parser.add_argument("--iface", default="en0")
    parser.add_argument("--freq", type=int, default=2412)
    parser.add_argument("--bssid", default="02:00:00:00:00:01")
    parser.add_argument("--model", default="tcn")
    parser.add_argument("--replay-pcap", default=None)
    parser.add_argument("-h", "--help", action="store_true")

    args, _ = parser.parse_known_args()

    if args.extcap_interfaces:
        extcap_interfaces()
        return
    if args.extcap_dlts:
        extcap_dlts(args.extcap_interface)
        return
    if args.extcap_config:
        extcap_config(args.extcap_interface)
        return
    if args.capture:
        if not args.fifo:
            sys.exit("Extcap capture requires --fifo")
        capture_stream(args.fifo, args.iface, args.freq, args.bssid, args.replay_pcap)
        return

    extcap_interfaces()


if __name__ == "__main__":
    main()
