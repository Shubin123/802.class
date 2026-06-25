#!/usr/bin/env python3
"""
dut_agent.py — runs ON THE DUT (the Wi-Fi traffic generator). Cross-platform
(macOS / Linux), stdlib only. Start it once; the orchestrator (collect.py on the
sniffer) connects over the CONTROL channel, syncs clocks, and commands which
service to load and for how long. The agent reports the exact start/stop time of
each traffic burst (its own clock), which the orchestrator converts to the
sniffer/pcap clock via the measured offset.

Topology note (both devices have Wi-Fi + Ethernet on one network):
  • Bind/reach this agent over the DUT's ETHERNET IP so control traffic stays OUT
    of the Wi-Fi capture.
  • Generated traffic must egress the DUT's Wi-Fi, or there's nothing to capture.
    With Wi-Fi and Ethernet on the same subnet the OS may prefer Ethernet, so we
    force it: `curl --interface <wlan>`. On Linux, run this agent as ROOT so curl
    can hard-bind the device (SO_BINDTODEVICE); otherwise it binds the source IP,
    which usually works but verify with the orchestrator's data-frame count.

Run on the DUT:
    python3 dut_agent.py --port 9999 --wifi-iface wlan0      # Linux DUT (sudo for hard bind)
    python3 dut_agent.py --port 9999 --wifi-iface en0        # macOS DUT
"""
import argparse
import os
import platform
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sync


def gen_curl(url, seconds, iface):
    """Loop fetches for `seconds`, forcing egress out `iface`. Returns request count."""
    base = ["curl", "-s", "-m", "10", "-o", os.devnull]
    if iface:
        base += ["--interface", iface]
    end = time.time() + seconds
    n = 0
    while time.time() < end:
        try:
            subprocess.run(base + [url], check=False)
        except Exception:
            pass
        n += 1
    return n


def gen_playwright(url, seconds, iface):
    """Delegate to dut_browse.py (a real headless browser) if present."""
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dut_browse.py")
    subprocess.run([sys.executable, script, "--url", url,
                    "--seconds", str(int(seconds)), "--iface", iface or ""], check=False)
    return -1  # request count not tracked for the browser driver


def handle_session(conn, args):
    while True:
        msg = sync.recv_msg(conn)
        if msg is None:
            return
        cmd = msg.get("cmd")

        if cmd == "hello":
            sync.send_msg(conn, {
                "ok": True, "role": "dut", "version": sync.PROTOCOL_VERSION,
                "platform": platform.system().lower(),
                "wifi_iface": args.wifi_iface, "root": (os.geteuid() == 0 if hasattr(os, "geteuid") else False),
                "time": time.time(),
            })

        elif cmd == "ping":
            t1 = time.time()
            sync.send_msg(conn, {"ok": True, "t1": t1, "t2": time.time()})

        elif cmd == "generate":
            url = msg["url"]
            seconds = float(msg.get("seconds", 60))
            driver = msg.get("driver", "curl")
            iface = msg.get("iface") or args.wifi_iface
            print(f"[dut_agent] generate '{url}' {seconds}s driver={driver} iface={iface}", flush=True)
            start = time.time()
            err = None
            try:
                n = gen_playwright(url, seconds, iface) if driver == "playwright" else gen_curl(url, seconds, iface)
                ok = True
            except Exception as e:
                n, ok, err = 0, False, str(e)
            end = time.time()
            sync.send_msg(conn, {"ok": ok, "start": start, "end": end,
                                 "requests": n, "iface": iface, "error": err})

        elif cmd == "bye":
            sync.send_msg(conn, {"ok": True})
            return

        else:
            sync.send_msg(conn, {"ok": False, "error": f"unknown cmd {cmd}"})


def main():
    ap = argparse.ArgumentParser(description="DUT-side traffic agent")
    ap.add_argument("--host", default="0.0.0.0", help="bind addr (default all; reach via Ethernet IP)")
    ap.add_argument("--port", type=int, default=sync.DEFAULT_PORT)
    ap.add_argument("--wifi-iface", default=None, help="iface that must carry the generated traffic")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(1)
    root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    print(f"[dut_agent] listening on {args.host}:{args.port}  platform={platform.system()}  "
          f"wifi_iface={args.wifi_iface}  root={root}", flush=True)
    if args.wifi_iface and platform.system() == "Linux" and not root:
        print("[dut_agent] WARNING: not root — curl will bind source IP, not the device. "
              "If captures come up empty, run with sudo for hard SO_BINDTODEVICE binding.", flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            print(f"[dut_agent] orchestrator connected from {addr}", flush=True)
            try:
                handle_session(conn, args)
            except Exception as e:
                print(f"[dut_agent] session error: {e}", flush=True)
            finally:
                conn.close()
                print("[dut_agent] session closed", flush=True)
    except KeyboardInterrupt:
        print("\n[dut_agent] shutting down")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
