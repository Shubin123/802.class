#!/usr/bin/env python3
"""
collect_ncat.py — REAL two-machine collection over ncat (no SSH). Runs ON THE MAC
in a shell that can reach the DUT on the LAN (use sudo for dumpcap).

The Windows DUT runs an ncat listener that hands each connection's bytes to PowerShell:
    ncat.exe -k -l 9999 --sh-exec "powershell -NoProfile -Command -"

This orchestrator, per (service, session):
    start dumpcap on en0  ->  ncat-send a curl.exe-over-Wi-Fi loop to the DUT for the
    window  ->  stop dumpcap  ->  count the DUT's data frames  ->  manifest row.

Capture + trigger are one process, so they share the Mac's pcap clock (that IS the
sync) and nothing is transferred by hand. Control (ncat) goes to the DUT's ETHERNET
ip — out of band; curl is bound to the Wi-Fi ip so the captured traffic egresses Wi-Fi.

  sudo python3 collect_ncat.py --dut-host <DUT_ETH_IP> --dut-port 9999 \
      --services services.csv --sessions 2 --duration 60 --eval
"""
import argparse
import csv
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent.resolve()


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


MARK = "zzZNCDONEZzz"


class DUT:
    """ONE persistent ncat control stream to the DUT's interactive PowerShell — reused for
    every command, so there's a single connection / single PowerShell on the DUT (not one
    per command, which piled up and wedged the listener). run() sends a single-line command
    + a marker, reads until the marker returns, and leaves the socket open for the next."""

    def __init__(self, host, port, timeout=15):
        self.s = socket.create_connection((host, int(port)), timeout=timeout)
        self.leftover = b""

    def run(self, command, timeout=120):
        mk = MARK.encode()
        self.s.sendall((command + f"\nWrite-Output '{MARK}'\n").encode())
        self.s.settimeout(timeout)
        out = self.leftover
        self.leftover = b""
        while mk not in out:
            try:
                d = self.s.recv(8192)
            except socket.timeout:
                break
            if not d:
                break
            out += d
        if mk in out:
            before, self.leftover = out.split(mk, 1)
            return before.decode(errors="replace")
        return out.decode(errors="replace")

    def close(self):
        try:
            self.s.sendall(b"exit\n")
        except OSError:
            pass
        try:
            self.s.close()
        except OSError:
            pass


def detect_wifi(dut):
    raw = dut.run("netsh wlan show interfaces", timeout=40)
    def g(k):
        m = re.search(rf"^\s*{k}\s*:\s*(.+?)\s*$", raw, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else None
    iface, mac, ssid = g("Name"), g("Physical address"), g("SSID")
    if mac:
        mac = mac.lower().replace("-", ":")
    chs = g("Channel")
    ch = re.search(r"\d+", chs).group(0) if chs else None
    freq = None
    if ch:
        c = int(ch)
        freq = 2484 if c == 14 else (2407 + 5 * c if c <= 14 else 5000 + 5 * c)
    ip = None
    if iface:
        ipraw = dut.run(f"(Get-NetIPAddress -InterfaceAlias '{iface}' -AddressFamily IPv4 -EA SilentlyContinue).IPAddress", timeout=20)
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", ipraw)
        ip = m.group(1) if m else None
    return {"iface": iface, "ip": ip, "mac": mac, "channel": ch, "freq": freq, "ssid": ssid, "raw": raw}


def drive(dut, url, wifi_ip, duration):
    iface = f"--interface {wifi_ip} " if wifi_ip else ""
    ps = (f"$e=(Get-Date).AddSeconds({duration}); $n=0; "
          f"while((Get-Date) -lt $e){{ curl.exe -s -m 10 -o NUL {iface}'{url}'; $n++ }}; "
          f'Write-Output "SENT=$n"')
    out = dut.run(ps, timeout=duration + 60)
    m = re.search(r"SENT=(\d+)", out)
    return (m.group(1) if m else "?"), out


def start_capture(args, out):
    # macOS dumpcap can't set 802.11 channels (-k); and if you've set monitor mode
    # yourself, --no-monitor drops -I too and just captures on the interface as-is.
    cmd = [args.dumpcap, "-i", args.iface]
    if not args.no_monitor:
        cmd.append("-I")
        if args.set_channel and args.freq:
            cmd += ["-k", str(args.freq)]
    cmd += ["-w", str(out), "-q"]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def stop_capture(proc):
    if proc is None:
        return ""
    proc.terminate()
    try:
        _, err = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill(); err = b""
    return (err or b"").decode(errors="replace")


def count_frames(args, out, mac):
    if not out.exists():
        return None
    tshark = str(Path(args.dumpcap).parent / "tshark")
    flt = "wlan.fc.type==2" + (f" && wlan.addr=={mac}" if mac else "")
    try:
        r = subprocess.run([tshark, "-r", str(out), "-Y", flt, "-T", "fields", "-e", "frame.number"],
                           capture_output=True, text=True, timeout=180)
        return sum(1 for l in r.stdout.splitlines() if l.strip())
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(
        description="Drive the Windows DUT (ncat listener) and capture on the Mac.",
        epilog="examples:\n"
               "  # 1) test comms only (no capture, no sudo):\n"
               "  python3 collect_ncat.py --dut-host 10.0.0.61 --no-capture\n"
               "  # 2) real run — you've put the capture iface in monitor mode on the AP channel:\n"
               "  sudo python3 collect_ncat.py --dut-host 10.0.0.61 --iface en0 --no-monitor --sessions 2 --duration 60\n"
               "\n(start the listener on the DUT first: run data\\real\\dut_listen.bat)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dut-host", required=True, help="DUT ip the Mac can reach (control)")
    ap.add_argument("--dut-port", type=int, default=9999)
    ap.add_argument("--services", default=str(HERE / "services.csv"))
    ap.add_argument("--out-dir", default=str(HERE / "sessions"))
    ap.add_argument("--manifest", default=str(HERE / "manifest.csv"))
    ap.add_argument("--sessions", type=int, default=2)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--guard", type=float, default=2.0)
    ap.add_argument("--drain", type=float, default=3.0)
    ap.add_argument("--idle", type=float, default=5.0)
    ap.add_argument("--iface", default="en0", help="Mac Wi-Fi iface for monitor capture")
    ap.add_argument("--freq", default=None, help="override capture channel freq (else from the DUT)")
    ap.add_argument("--wifi-ip", default=None, help="override DUT Wi-Fi ip (curl --interface)")
    ap.add_argument("--wifi-mac", default=None, help="override DUT Wi-Fi MAC (frame filter)")
    ap.add_argument("--dumpcap", default="/Applications/Wireshark.app/Contents/MacOS/dumpcap")
    ap.add_argument("--no-capture", action="store_true", help="trigger only (validate comms)")
    ap.add_argument("--no-monitor", action="store_true",
                    help="don't set monitor mode — capture on --iface as-is (you set monitor + channel yourself)")
    ap.add_argument("--set-channel", action="store_true",
                    help="pass dumpcap -k to set the channel (NOT supported on macOS; default off)")
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--checkpoint", default=str(HERE / ".." / ".." / "train" / "checkpoints" / "best_resnet.pt.600epoch"))
    args = ap.parse_args()

    if not args.no_capture:
        r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True)
        def_if = next((l.split()[-1] for l in r.stdout.splitlines() if "interface:" in l), "")
        if def_if == args.iface:
            sys.exit(f"default route is {args.iface} (Wi-Fi); put Ethernet first or monitor mode drops you offline.")

    log(f"probing DUT ncat at {args.dut_host}:{args.dut_port} …")
    try:
        dut = DUT(args.dut_host, args.dut_port)
    except OSError as e:
        sys.exit(f"could not reach DUT ncat at {args.dut_host}:{args.dut_port}: {e}\n"
                 f"  -> run dut_listen.bat on the DUT and open port {args.dut_port} in its firewall.")

    services = list(csv.DictReader(open(args.services)))
    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    try:
        wifi = detect_wifi(dut)
        wifi_ip = args.wifi_ip or wifi["ip"]
        wifi_mac = (args.wifi_mac or wifi["mac"] or "").lower().replace("-", ":") or None
        if not args.freq:
            args.freq = wifi["freq"]
        log(f"DUT Wi-Fi: iface={wifi['iface']} ip={wifi_ip} mac={wifi_mac} ch={wifi['channel']} freq={args.freq}")
        if not (wifi_ip and wifi_mac):
            log("⚠ Wi-Fi not fully detected — is wlan associated?")
            log("  raw DUT reply:\n" + (wifi["raw"][:400] or "(empty)"))
            if not args.no_capture:
                sys.exit("  pass --wifi-ip / --wifi-mac to override, then retry.")

        for s in range(1, args.sessions + 1):
            for svc in services:
                label, name, url = svc["label"].strip(), svc["name"].strip(), svc["url"].strip()
                out = out_dir / f"{label}__{name}__s{s}.pcapng"
                log(f"{name} (label {label}) s{s} -> {out.name}")
                proc = None if args.no_capture else start_capture(args, out)
                time.sleep(args.guard)
                t0 = time.time()
                sent, _ = drive(dut, url, wifi_ip, args.duration)
                log(f"    traffic done in {time.time()-t0:.0f}s (sent={sent})")
                time.sleep(args.drain)
                cerr = stop_capture(proc)
                if not args.no_capture:
                    n = count_frames(args, out, wifi_mac)
                    if n is None and cerr:
                        log(f"    ⚠ dumpcap: {cerr[:140]}")
                    else:
                        flag = "  ⚠ LOW — wrong MAC, or the interface isn't on the AP channel" if (n or 0) < 128 else ""
                        log(f"    {n} data frames for {wifi_mac}{flag}")
                    rows.append({"pcap": f"sessions/{out.name}", "mac": wifi_mac, "label": label, "session": f"s{s}"})
                time.sleep(args.idle)
    finally:
        dut.close()

    if rows:
        with open(args.manifest, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["pcap", "mac", "label", "session"])
            w.writeheader(); w.writerows(rows)
        log(f"manifest: {args.manifest} ({len(rows)} captures)")
        if args.eval:
            log("running eval_real.py …")
            subprocess.run([sys.executable, str(HERE / ".." / ".." / "infer" / "eval_real.py"),
                            "--manifest", args.manifest, "--checkpoint", args.checkpoint])


if __name__ == "__main__":
    main()
