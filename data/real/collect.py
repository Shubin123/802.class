#!/usr/bin/env python3
"""
collect.py — automated, clock-SYNCED, two-device real-data collection.

One controller (this script, on the sniffer/Mac) starts the capture AND drives a
separate DUT to generate one service's traffic, so every capture file maps to
exactly one service by construction. With --transport agent it speaks to
dut_agent.py over a control channel, measures the clock offset (sync.py), and
records each traffic window IN THE SNIFFER'S CLOCK (the pcap clock) — so labels are
verifiable to the millisecond and a future continuous-capture / time-slice mode is
possible.

Topology (both devices have Wi-Fi + Ethernet on one network):
  [ sniffer+orchestrator ]  Wi-Fi en0 in MONITOR; online + control over ETHERNET
        | TCP control to the DUT's ETHERNET IP  (out-of-band; never in the capture)
        v
  [ DUT ]  runs dut_agent.py; browses over its WI-FI iface (forced via curl --interface)

Per (service, session): start capture → wait GUARD → command DUT to load the
service for DURATION → wait DRAIN → stop capture → count data frames → wait IDLE.

Start the DUT side first:
    # on the DUT:
    python3 dut_agent.py --port 9999 --wifi-iface wlan0      # (sudo on Linux for hard bind)

Then one command here:
    # dry run (validates timing + agent RPC if --dut-host given; no capture):
    python collect.py --services services.example.csv --transport agent \
        --dut-host <DUT_ETH_IP> --no-capture --sessions 1 --duration 3

    # real run (Ethernet must be the Mac's default route — refused otherwise):
    sudo python collect.py --services services.csv --transport agent \
        --dut-host <DUT_ETH_IP> --dut-wifi-mac aa:bb:cc:dd:ee:ff --dut-wifi-iface wlan0 \
        --freq 5785 --sessions 3 --duration 60 --eval
"""
import argparse
import csv
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent.resolve()
sys.path.insert(0, str(HERE))
import sync  # noqa: E402


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ── capture (sniffer side) ────────────────────────────────────────────────────
def start_capture(args, out):
    if args.dry_run or args.no_capture:
        log(f"    [capture] (skipped) dumpcap -i {args.iface} -I -k {args.freq} -w {out.name}")
        return None
    cmd = [args.dumpcap, "-i", args.iface, "-I", "-w", str(out), "-q"]
    if args.freq:
        cmd[4:4] = ["-k", str(args.freq)]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_capture(proc):
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def count_data_frames(args, out, mac):
    if args.dry_run or args.no_capture or not out.exists():
        return None
    tshark = str(Path(args.dumpcap).parent / "tshark")
    flt = "wlan.fc.type==2" + (f" && wlan.addr=={mac}" if mac else "")
    try:
        r = subprocess.run([tshark, "-r", str(out), "-Y", flt, "-T", "fields", "-e", "frame.number"],
                           capture_output=True, text=True, timeout=180)
        return sum(1 for line in r.stdout.splitlines() if line.strip())
    except Exception:
        return None


# ── traffic trigger (DUT side), returns (t_start, t_end) in ORCH/pcap clock ───
def trigger_agent(client, args, url, sid):
    r = client.generate(url, args.duration, driver=args.traffic,
                        iface=args.dut_wifi_iface, sid=sid)
    return client.dut_to_orch(r["start"]), client.dut_to_orch(r["end"]), r.get("requests")


def trigger_nc(args, url):
    """Keyless netcat path: push a self-contained command to the DUT's `dut_listen.sh`
    over a plain TCP socket on the LAN (no SSH, no keys). No clock handshake, so the
    window is bracketed in the orchestrator clock — fine for one-file-per-service."""
    ifaceflag = f"--interface {args.dut_wifi_iface} " if args.dut_wifi_iface else ""
    if args.traffic == "playwright":
        body = f"python3 ~/dut_browse.py --url '{url}' --seconds {args.duration} --iface {args.dut_wifi_iface or ''}"
    else:
        body = (f"end=$(( $(date +%s) + {args.duration} )); "
                f"while [ $(date +%s) -lt $end ]; do curl -s -m 10 {ifaceflag}-o /dev/null '{url}' || true; done")
    payload = (body + "\n").encode()
    t0 = time.time()
    for _ in range(20):                       # the nc listener re-spawns between services
        try:
            with socket.create_connection((args.dut_host, args.dut_port), timeout=5) as s:
                s.sendall(payload)
            break
        except OSError:
            time.sleep(0.25)
    else:
        raise RuntimeError(f"could not reach DUT nc listener at {args.dut_host}:{args.dut_port}")
    time.sleep(args.duration)                  # DUT runs the command for ~duration
    return t0, time.time(), None


def trigger_local(args, url):
    """Testing only — egress follows the local default route (likely NOT captured)."""
    t0 = time.time()
    end = t0 + args.duration
    n = 0
    while time.time() < end:
        subprocess.run(["curl", "-s", "-m", "10", "-o", "/dev/null", url], check=False)
        n += 1
    return t0, time.time(), n


# ── orchestration ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Automated clock-synced 802.11 capture collection")
    ap.add_argument("--services", required=True, help="CSV: label,name,url")
    ap.add_argument("--out-dir", default=str(HERE / "sessions"))
    ap.add_argument("--manifest", default=str(HERE / "manifest.csv"))
    ap.add_argument("--sessions", type=int, default=2)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--guard", type=float, default=2.0)
    ap.add_argument("--drain", type=float, default=3.0)
    ap.add_argument("--idle", type=float, default=5.0)
    # capture (sniffer)
    ap.add_argument("--iface", default="en0", help="Mac Wi-Fi interface for monitor capture")
    ap.add_argument("--freq", default=None, help="channel for dumpcap -k, e.g. 5785 or 5785,VHT80,5775")
    ap.add_argument("--dumpcap", default="/Applications/Wireshark.app/Contents/MacOS/dumpcap")
    ap.add_argument("--no-capture", action="store_true", help="skip dumpcap (test sync/traffic only)")
    # DUT control
    ap.add_argument("--transport", choices=["agent", "nc", "local"], default="agent",
                    help="agent=synced TCP (recommended); nc=keyless netcat; local=single-host test")
    ap.add_argument("--traffic", choices=["curl", "playwright"], default="curl")
    ap.add_argument("--dut-host", default=None, help="DUT ETHERNET ip/host (agent + nc transports)")
    ap.add_argument("--dut-port", type=int, default=sync.DEFAULT_PORT)
    ap.add_argument("--dut-wifi-mac", default=None, help="DUT Wi-Fi MAC → manifest 'mac'")
    ap.add_argument("--dut-wifi-iface", default=None, help="DUT Wi-Fi iface (curl --interface)")
    # after
    ap.add_argument("--eval", action="store_true", help="run eval_real.py on the manifest when done")
    ap.add_argument("--checkpoint", default=str(HERE / ".." / ".." / "train" / "checkpoints" / "best_resnet.pt.600epoch"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    # validation
    if not args.dry_run:
        if args.transport in ("agent", "nc") and not args.dut_host:
            ap.error(f"--dut-host (DUT Ethernet IP) is required for --transport {args.transport}")
        if not args.no_capture and not args.freq:
            ap.error("--freq is required for real capture (or pass --no-capture)")
        if not args.no_capture and not args.dut_wifi_mac:
            ap.error("--dut-wifi-mac is required (it becomes the manifest 'mac')")
        if not args.no_capture:
            try:
                r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True)
                def_if = next((l.split()[-1] for l in r.stdout.splitlines() if "interface:" in l), "")
                if def_if == args.iface:
                    ap.error(f"default route is {args.iface} (Wi-Fi); activate Ethernet first or monitor "
                             f"mode drops you offline (README §1).")
            except Exception:
                pass

    services = list(csv.DictReader(open(args.services)))
    if not services or not {"label", "name", "url"}.issubset(services[0].keys()):
        print("services CSV needs header: label,name,url"); sys.exit(1)

    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    mac = args.dut_wifi_mac or "DUT_WIFI_MAC"

    # connect + clock-sync the DUT agent
    client = None
    if args.transport == "agent" and args.dut_host:
        client = sync.AgentClient(args.dut_host, args.dut_port)
        info = client.connect()
        off, delay = client.sync_clock()
        log(f"DUT agent: {info.get('platform')} root={info.get('root')} wifi={info.get('wifi_iface')}")
        log(f"clock sync: offset={off*1000:+.1f} ms  rtt={delay*1000:.1f} ms "
            f"(orch_time = dut_time {-off:+.4f}s)")

    per = args.guard + args.duration + args.drain + args.idle
    log(f"plan: {len(services)} services x {args.sessions} sessions "
        f"(~{per*len(services)*args.sessions/60:.1f} min){' [DRY RUN]' if args.dry_run else ''}")

    rows = []
    try:
        for s in range(1, args.sessions + 1):
            for svc in services:
                label, name, url = svc["label"].strip(), svc["name"].strip(), svc["url"].strip()
                out = out_dir / f"{label}__{name}__s{s}.pcapng"
                log(f"capture {name} (label {label}) s{s} -> {out.name}")

                t_clock0 = time.time()
                proc = start_capture(args, out)
                time.sleep(args.guard)
                log(f"    +{time.time()-t_clock0:.1f}s guard done; driving traffic {args.duration}s")

                if args.dry_run:
                    time.sleep(min(args.duration, 1)); ts, te, nreq = t_clock0, time.time(), None
                elif args.transport == "agent":
                    ts, te, nreq = trigger_agent(client, args, url, f"{label}_s{s}")
                elif args.transport == "nc":
                    ts, te, nreq = trigger_nc(args, url)
                else:
                    ts, te, nreq = trigger_local(args, url)

                log(f"    +{time.time()-t_clock0:.1f}s traffic done"
                    + (f" ({nreq} reqs)" if nreq not in (None, -1) else "") + f"; draining {args.drain}s")
                time.sleep(args.drain)
                stop_capture(proc)

                n = count_data_frames(args, out, mac)
                if n is not None:
                    flag = "  ⚠ LOW — egress may have gone over Ethernet; check routing/iface/channel" if n < 128 else ""
                    log(f"    +{time.time()-t_clock0:.1f}s stopped; {n} data frames for {mac}{flag}")
                else:
                    log(f"    +{time.time()-t_clock0:.1f}s stopped")

                rows.append({"pcap": f"sessions/{out.name}", "mac": mac, "label": label,
                            "session": f"s{s}", "t_start": f"{ts:.3f}", "t_end": f"{te:.3f}"})
                time.sleep(args.idle)
    finally:
        if client:
            client.close()

    mpath = Path(args.manifest)
    with open(mpath, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["pcap", "mac", "label", "session", "t_start", "t_end"])
        w.writeheader(); w.writerows(rows)
    log(f"wrote manifest: {mpath}  ({len(rows)} captures)")

    if args.eval and not args.dry_run and not args.no_capture:
        log("running eval_real.py …")
        subprocess.run([sys.executable, str(HERE / ".." / ".." / "infer" / "eval_real.py"),
                        "--manifest", str(mpath), "--checkpoint", args.checkpoint])


if __name__ == "__main__":
    main()
