#!/usr/bin/env python3
"""
collect_ncat.py — REAL two-machine capture over ncat, built for a ONE-RADIO Mac where
monitor mode knocks the network out (so we can't talk to the DUT *while* capturing).

Decoupled flow (control only happens when monitor is OFF):
  1. ncat → DUT: detect Wi-Fi, then launch an AUTONOMOUS schedule on the DUT (a detached
     PowerShell that browses each service over Wi-Fi for `duration`, logging timestamps).
  2. start ONE continuous monitor capture on the Mac and just wait — no network needed.
  3. stop the capture (network comes back), reconnect, pull the DUT's timestamp log.
  4. slice the one capture into per-service pcaps by those timestamps + the DUT MAC.

Nothing is pasted by hand; the schedule + log move over ncat automatically.

DUT (Windows): runs dut_listen.bat (ncat + PowerShell) + curl.exe. Mac: dumpcap (sudo),
Wi-Fi iface already in monitor mode on the AP channel (macOS dumpcap can't set channel).

  sudo python3 collect_ncat.py --dut-host 10.0.0.61 --iface en0 --no-monitor --sessions 2 --duration 60
"""
import argparse
import base64
import csv
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent.resolve()
MARK = "zzZNCDONEZzz"
DUT_PS = r"C:\Users\Public\dut_sched.ps1"
DUT_LOG = r"C:\Users\Public\dut_run.csv"


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


# ── ncat control (one persistent stream, used only while monitor is OFF) ──────
class DUT:
    def __init__(self, host, port, timeout=15):
        self.s = socket.create_connection((host, int(port)), timeout=timeout)
        self.leftover = b""

    def run(self, command, timeout=60):
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


def connect_retry(host, port, deadline=60):
    """Reconnect after monitor mode (the network takes a moment to come back)."""
    end = time.time() + deadline
    last = None
    while time.time() < end:
        try:
            return DUT(host, port)
        except OSError as e:
            last = e
            time.sleep(2)
    raise SystemExit(f"could not reach DUT ncat at {host}:{port} after monitor: {last}")


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


# ── autonomous schedule on the DUT ────────────────────────────────────────────
def build_schedule(services, sessions, duration, idle, wifi_ip, initial_delay):
    iface = f"--interface {wifi_ip} " if wifi_ip else ""
    L = [f"Set-Content -Path '{DUT_LOG}' -Value 'label,name,session,start,end'",
         f"Start-Sleep -Seconds {initial_delay}"]
    for s in range(1, sessions + 1):
        for svc in services:
            label, name, url = svc["label"].strip(), svc["name"].strip(), svc["url"].strip()
            L += [
                "$st=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0",
                f"$e=(Get-Date).AddSeconds({duration})",
                f"while((Get-Date) -lt $e){{ curl.exe -s -m 10 -o NUL {iface}'{url}' }}",
                "$en=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0",
                f"Add-Content -Path '{DUT_LOG}' -Value \"{label},{name},s{s},$st,$en\"",
                f"Start-Sleep -Seconds {idle}",
            ]
    return "\r\n".join(L)


def fire_schedule(dut, ps_script):
    b64 = base64.b64encode(ps_script.encode("utf-8")).decode()
    dut.run(f"[IO.File]::WriteAllText('{DUT_PS}',[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}')))", timeout=30)
    dut.run(f"Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{DUT_PS}'", timeout=20)


def fetch_log(dut):
    out = dut.run(f"Get-Content '{DUT_LOG}'", timeout=30)
    rows = []
    for line in out.splitlines():
        p = line.strip().split(",")
        if len(p) == 5 and p[0] != "label" and re.match(r"[\d.]+", p[3] or ""):
            rows.append({"label": p[0], "name": p[1], "session": p[2],
                         "start": float(p[3]), "end": float(p[4])})
    return rows


# ── capture (Mac) ─────────────────────────────────────────────────────────────
def start_capture(args, out):
    cmd = [args.dumpcap, "-i", args.iface]
    if not args.no_monitor:
        cmd.append("-I")
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


def tshark(args):
    return str(Path(args.dumpcap).parent / "tshark")


def slice_capture(args, cap, rows, mac, out_dir, guard=1.0):
    manifest = []
    for r in rows:
        out = out_dir / f"{r['label']}__{r['name']}__{r['session']}.pcapng"
        flt = (f"frame.time_epoch >= {r['start']+guard} && frame.time_epoch <= {r['end']-guard} "
               f"&& wlan.fc.type == 2" + (f" && wlan.addr == {mac}" if mac else ""))
        subprocess.run([tshark(args), "-r", str(cap), "-Y", flt, "-w", str(out)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        n = 0
        if out.exists():
            c = subprocess.run([tshark(args), "-r", str(out), "-T", "fields", "-e", "frame.number"],
                               capture_output=True, text=True)
            n = sum(1 for l in c.stdout.splitlines() if l.strip())
        flag = "  ⚠ LOW" if n < 128 else ""
        log(f"    {r['name']:12} {r['session']}  label {r['label']:>3}  {n:5d} data frames{flag}")
        manifest.append({"pcap": f"sessions/{out.name}", "mac": mac, "label": r["label"], "session": r["session"]})
    return manifest


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Autonomous-schedule capture: DUT browses on its own while the Mac captures.",
        epilog="example:\n"
               "  sudo python3 collect_ncat.py --dut-host 10.0.0.61 --iface en0 --no-monitor --sessions 2 --duration 60\n"
               "(start dut_listen.bat on the DUT first; put --iface in monitor mode on the AP channel)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dut-host", required=True)
    ap.add_argument("--dut-port", type=int, default=9999)
    ap.add_argument("--services", default=str(HERE / "services.csv"))
    ap.add_argument("--out-dir", default=str(HERE / "sessions"))
    ap.add_argument("--capture", default=str(HERE / "capture.pcapng"))
    ap.add_argument("--manifest", default=str(HERE / "manifest.csv"))
    ap.add_argument("--sessions", type=int, default=2)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--idle", type=int, default=5)
    ap.add_argument("--initial-delay", type=int, default=8, help="DUT waits this long before traffic (capture warm-up)")
    ap.add_argument("--iface", default="en0")
    ap.add_argument("--no-monitor", action="store_true", help="don't pass dumpcap -I (you set monitor yourself)")
    ap.add_argument("--wifi-ip", default=None)
    ap.add_argument("--wifi-mac", default=None)
    ap.add_argument("--dumpcap", default="/Applications/Wireshark.app/Contents/MacOS/dumpcap")
    ap.add_argument("--no-capture", action="store_true", help="run the schedule + fetch log only (no capture/slice)")
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--checkpoint", default=str(HERE / ".." / ".." / "train" / "checkpoints" / "best_resnet.pt.600epoch"))
    args = ap.parse_args()

    services = list(csv.DictReader(open(args.services)))
    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    total = args.initial_delay + args.sessions * len(services) * (args.duration + args.idle) + 8

    # 1. control phase (monitor OFF): detect Wi-Fi + launch the autonomous schedule
    log(f"connecting DUT ncat {args.dut_host}:{args.dut_port} …")
    dut = connect_retry(args.dut_host, args.dut_port, deadline=30)
    wifi = detect_wifi(dut)
    wifi_ip = args.wifi_ip or wifi["ip"]
    wifi_mac = (args.wifi_mac or wifi["mac"] or "").lower().replace("-", ":") or None
    log(f"DUT Wi-Fi: iface={wifi['iface']} ip={wifi_ip} mac={wifi_mac} ch={wifi['channel']} freq={wifi['freq']}")
    if not (wifi_ip and wifi_mac):
        log("⚠ Wi-Fi not detected: " + (wifi["raw"][:300] or "(empty — is the ncat listener up?)"))
        sys.exit("  pass --wifi-ip / --wifi-mac to override.")
    ps = build_schedule(services, args.sessions, args.duration, args.idle, wifi_ip, args.initial_delay)
    fire_schedule(dut, ps)
    dut.close()
    log(f"DUT schedule launched: {len(services)} services x {args.sessions} sessions (~{total}s). "
        f"Make sure {args.iface} is in monitor mode on ch{wifi['channel']}.")

    # 2. capture phase (monitor ON; network drops — that's fine, nothing to talk to)
    cap = Path(args.capture)
    proc = None
    if not args.no_capture:
        proc = start_capture(args, cap)
        log(f"capturing on {args.iface}{' -I' if not args.no_monitor else ' (no -I)'} → {cap.name}")
    waited = 0
    while waited < total:
        time.sleep(min(15, total - waited)); waited += 15
        log(f"  … {min(waited, total)}/{total}s")
    cerr = stop_capture(proc)
    if cerr:
        log(f"  dumpcap note: {cerr[:160]}")

    # 3. control phase again (monitor OFF; network back): pull the timestamp log
    log("schedule done; reconnecting to pull the DUT timestamps …")
    time.sleep(5)
    dut2 = connect_retry(args.dut_host, args.dut_port, deadline=60)
    rows = fetch_log(dut2)
    dut2.close()
    if not rows:
        sys.exit("DUT log empty — the schedule may not have run (check the DUT).")
    log(f"DUT ran {len(rows)} windows (real start/end timestamps).")

    if args.no_capture:
        for r in rows:
            log(f"    {r['name']:12} {r['session']}  [{r['start']:.0f}..{r['end']:.0f}]")
        return

    # 4. slice the one capture by the DUT timestamps + MAC
    log(f"slicing {cap.name} into per-service captures …")
    manifest = slice_capture(args, cap, rows, wifi_mac, out_dir)
    with open(args.manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["pcap", "mac", "label", "session"])
        w.writeheader(); w.writerows(manifest)
    log(f"manifest: {args.manifest} ({len(manifest)} captures)")
    if args.eval:
        subprocess.run([sys.executable, str(HERE / ".." / ".." / "infer" / "eval_real.py"),
                        "--manifest", args.manifest, "--checkpoint", args.checkpoint])


if __name__ == "__main__":
    main()
