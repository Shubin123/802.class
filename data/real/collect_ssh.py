#!/usr/bin/env python3
"""Mac passive collector + Linux/CM4 Wi-Fi DUT, controlled over SSH.

Traffic runs detached on the DUT so Wi-Fi SSH control is closed during capture.
The AP must already be configured; this tool never changes its security mode.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from wifi_app.capture import scope_pcap


def run_capture(command, timeout):
    """Release the capture device before recovery, even on cancellation."""
    process = subprocess.Popen(command, start_new_session=True)
    try:
        code = process.wait(timeout=timeout)
        if code:
            raise subprocess.CalledProcessError(code, command)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dut-host', required=True, help='SSH alias or user@host')
    p.add_argument('--ssh-option', action='append', default=[], help='Repeat for SSH -o options, e.g. ProxyCommand=...')
    p.add_argument('--wifi-interface', default='wlan0')
    p.add_argument('--interface', default='en0', help='Mac monitor interface, already on DUT channel')
    p.add_argument('--security', required=True, choices=['wpa2', 'wpa3'], help='Expected AP security; WPA3 requires SAE-only RSN evidence')
    p.add_argument('--label', required=True, help='Activity label; URL fetches are not full native app sessions')
    p.add_argument('--url', required=True)
    p.add_argument('--sessions', type=int, default=3)
    p.add_argument('--duration', type=int, default=30)
    p.add_argument('--out', type=Path, default=ROOT / 'data/field/cm4')
    p.add_argument('--no-monitor', action='store_true')
    p.add_argument('--prepare-monitor', help='Executable and arguments run after SSH closes; {interface} and {frequency} are substituted. No shell is used.')
    p.add_argument('--restore-network', help='Command always run after capture/preparation, including failure; same substitutions as --prepare-monitor')
    args = p.parse_args()
    if args.prepare_monitor and not args.restore_network:
        p.error('--prepare-monitor requires --restore-network to restore normal Wi-Fi on exit')
    if not args.url.startswith(('https://', 'http://')):
        p.error('URL must use http:// or https://')
    if args.duration < 5 or args.sessions < 1:
        p.error('duration must be >=5 and sessions must be positive')
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15']
    for option in args.ssh_option:
        ssh += ['-o', option]
    ssh += [args.dut_host]

    def remote(command, *, reconnect=False):
        deadline = time.monotonic() + (60 if reconnect else 0)
        while True:
            completed = subprocess.run(ssh + [command], capture_output=True, text=True, timeout=30)
            if completed.returncode == 0:
                return completed.stdout
            if not reconnect or completed.returncode != 255 or time.monotonic() >= deadline:
                raise subprocess.CalledProcessError(completed.returncode, ssh + [command],
                                                    completed.stdout, completed.stderr)
            time.sleep(2)

    iface = shlex.quote(args.wifi_interface)
    link = remote(f'iw dev {iface} link')
    if 'Connected to ' not in link:
        p.error('DUT Wi-Fi is not associated')
    bssid = link.split('Connected to ', 1)[1].split()[0].lower()
    match = re.search(r'freq:\s*([0-9.]+)', link)
    if not match:
        p.error('cannot determine DUT channel frequency')
    frequency = int(float(match.group(1)))
    mac = remote(f'cat /sys/class/net/{iface}/address').strip()
    scan = remote(f'iw dev {iface} scan dump')
    block = next((b for b in scan.split('BSS ') if b.startswith(bssid)), '')
    auth = [line for line in block.splitlines() if 'Authentication suites:' in line]
    if not auth or not any(cipher in block for cipher in ('CCMP', 'GCMP')):
        p.error('cannot verify target BSSID RSN/CCMP/GCMP security')
    suites = auth[0].split('Authentication suites:', 1)[1].split()
    expected = 'PSK' if args.security == 'wpa2' else 'SAE'
    if set(suites) != {expected}:
        p.error(f'expected {expected}-only AP; found {suites}. Transition mode does not prove negotiated WPA3.')
    args.out.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:12]
    (args.out / f'{run_id}.preflight.json').write_text(json.dumps({
        'dut_host': args.dut_host, 'link': link, 'rsn_scan': block,
        'security': args.security, 'client_mac': mac,
        'label': args.label, 'url': args.url,
        'control': 'SSH disconnected during capture; detached DUT traffic',
    }, indent=2))
    manifest = args.out / 'manifest.csv'
    columns = ['pcap', 'bssid', 'client_mac', 'label', 'session_id', 'device_id', 'ap_id',
               'collection_day', 'security', 'capture_radio']
    for ordinal in range(args.sessions):
        current_link = remote(f'iw dev {iface} link')
        if f'Connected to {bssid}' not in current_link or not re.search(rf'freq:\s*{frequency}(?:\.0)?\s', current_link):
            p.error('DUT roamed or changed channel; rerun collection after it stabilizes')
        sid = f'cm4-{args.security}-{run_id}-{ordinal:03d}'
        capture = args.out / f'{sid}.pcapng'
        # Fail before generating DUT traffic if capture access/monitor mode is unavailable.
        probe = ['dumpcap', '-i', args.interface, '-L'] + ([] if args.no_monitor else ['-I'])
        checked = subprocess.run(probe, capture_output=True, text=True, timeout=20)
        if checked.returncode:
            p.error('capture preflight failed: ' + checked.stderr.strip())
        if 'IEEE802_11' not in checked.stdout + checked.stderr:
            p.error('capture interface does not offer raw 802.11 link types')
        log = f'/tmp/{sid}.json'
        code = f'''import json,subprocess,time
result={{"success":0,"failures":0,"url":{args.url!r},"label":{args.label!r}}}
time.sleep(5)
end=time.monotonic()+{args.duration - 4}
while time.monotonic()<end:
 r=subprocess.run(["curl","--interface",{args.wifi_interface!r},"--fail","--silent","--show-error","--max-time","3","--output","/dev/null",{args.url!r}],capture_output=True)
 result["success" if r.returncode==0 else "failures"]+=1
 time.sleep(0.2)
open({log!r},"w").write(json.dumps(result))
'''
        remote('nohup python3 -c ' + shlex.quote(code) + ' </dev/null >/dev/null 2>&1 &')
        started = time.monotonic()
        try:
            if args.prepare_monitor:
                prepare = [part.format(interface=args.interface, frequency=frequency)
                           for part in shlex.split(args.prepare_monitor)]
                subprocess.run(prepare, check=True, timeout=3)
            command = ['dumpcap', '-i', args.interface, '-w', str(capture), '-a',
                       f'duration:{args.duration + 7}', '-q']
            if not args.no_monitor:
                command.append('-I')
            run_capture(command, timeout=args.duration + 40)
        finally:
            if args.restore_network:
                restore = [part.format(interface=args.interface, frequency=frequency)
                           for part in shlex.split(args.restore_network)]
                subprocess.run(restore, check=True, timeout=60)
        remaining = args.duration + 8 - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)
        result = json.loads(remote('cat ' + shlex.quote(log), reconnect=True))
        frames, counts = scope_pcap(capture, bssid, client_mac=mac)
        protected = sum(f.observation.protected for f in frames)
        directions = {d: sum(f.observation.protected and f.direction == d for f in frames)
                      for d in ('uplink', 'downlink')}
        result.update({'protected_frames': protected, 'directions': directions, 'scope_counts': counts})
        capture.with_suffix('.quality.json').write_text(json.dumps(result, indent=2))
        if result['success'] == 0 or result['failures'] or protected < 16 or not all(directions.values()):
            raise RuntimeError(f'{sid}: unusable labeled capture: {result}')
        exists = manifest.exists() and manifest.stat().st_size > 0
        with manifest.open('a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            if not exists:
                writer.writeheader()
            writer.writerow(dict(zip(columns, [capture.name, bssid, mac, args.label, sid,
                'cm4', bssid, time.strftime('%Y-%m-%d'), args.security, args.interface])))
        print(json.dumps({'session': sid, **result}), flush=True)
    print(f'Manifest: {manifest}')


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except subprocess.CalledProcessError as exc:
        sys.exit(f'command failed ({exc.returncode}): {exc.cmd}\n{exc.stderr or ""}')
    except (subprocess.TimeoutExpired, RuntimeError) as exc:
        sys.exit(str(exc))
