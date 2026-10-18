#!/usr/bin/env python3
"""Local CM4 framebuffer UI. No browser, Mac, or network service is required."""
from __future__ import annotations

import argparse
import csv
import json
import mmap
import os
import select
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def status(root=ROOT):
    verification = read_json(root / 'data/field/install-check/verification.json')
    legacy = read_json(root / 'data/dataset_output_old/dataset.local-report.json')
    evaluation = read_json(root / 'data/field/cm4/evaluation.json')
    inference = read_json(root / 'data/field/cm4/independent-inference.json')
    demo = not inference
    if demo:
        inference = read_json(root / 'data/field/install-check/tcn.inference.json')
    sessions = inference.get('sessions', [])
    prediction = next((s.get('prediction') for s in sessions if s.get('prediction')), 'No result yet')
    if demo and prediction != 'No result yet':
        prediction = f'Synthetic demo: {prediction}'
    return {
        'demo': demo,
        'legacy_rows': legacy.get('rows'),
        'legacy_classes': legacy.get('classes'),
        'runtime': verification.get('status', 'Not checked'),
        'host': verification.get('host', 'CM4 / Lakka'),
        'samples': evaluation.get('samples', 0),
        'sessions': evaluation.get('source_sessions', 0),
        'wpa2': evaluation.get('wpa2_status', 'Awaiting labeled captures'),
        'wpa3': evaluation.get('wpa3_status', 'Not tested: SAE test AP required'),
        'prediction': prediction,
        'scope': ('Synthetic demo only; real activity model not available.' if demo
                  else evaluation.get('scope', 'Real capture inference; field accuracy not established.')),
    }


def render(info, message='Ready', busy=False):
    from PIL import Image, ImageDraw, ImageFont
    image = Image.new('RGB', (960, 540), '#0b1220')
    d = ImageDraw.Draw(image)
    title = ImageFont.load_default(size=34)
    font = ImageFont.load_default(size=22)
    small = ImageFont.load_default(size=18)
    d.text((30, 22), 'Wi-Fi Classifier', font=title, fill='#f3f6ff')
    d.text((30, 66), f"{info['host']}  |  Runs locally on this device", font=small, fill='#9baac3')
    d.rounded_rectangle((28, 108, 932, 169), radius=12, fill='#142a29')
    d.text((45, 122), f"Runtime: {info['runtime']}   |   {'Working...' if busy else message}"[:88], font=font, fill='#77ebbd')
    lines = [
        ('REAL DATA', f"{info['samples']} windows / {info['sessions']} source sessions"),
        ('WPA2', str(info['wpa2'])),
        ('WPA3', str(info['wpa3'])),
        ('LATEST RESULT', str(info['prediction'])),
    ]
    for n, (label, value) in enumerate(lines):
        y = 198 + n * 55
        d.text((32, y), label, font=small, fill='#8e9eb9')
        d.text((228, y - 3), value[:61], font=font, fill='#eef3ff')
    d.text((32, 427), str(info['scope'])[:92], font=small, fill='#aebcd3')
    if info.get('legacy_rows') is not None:
        d.text((32, 451), f"Local replay dataset: {info['legacy_rows']:,} packets / {info['legacy_classes']} classes",
               font=small, fill='#8e9eb9')
    d.rounded_rectangle((28, 475, 932, 520), radius=10, fill='#1d2a41')
    d.text((44, 487), 'A: Offline check     X: Classify sample     B: Return to Lakka', font=small, fill='#d5e3ff')
    return image


class Framebuffer:
    def __init__(self, device):
        self.name = Path(device).name
        base = Path('/sys/class/graphics') / self.name
        _, virtual_height = map(int, (base / 'virtual_size').read_text().strip().split(','))
        self.bits = int((base / 'bits_per_pixel').read_text())
        self.stride = int((base / 'stride').read_text())
        if self.bits not in (16, 32):
            raise RuntimeError(f'unsupported framebuffer: {self.bits} bits')
        # fb_var_screeninfo: red/green/blue/transparency bitfields start at byte 32.
        import fcntl
        import array
        var = array.array('B', bytes(160))
        self.fd = os.open(device, os.O_RDWR)
        try:
            fcntl.ioctl(self.fd, 0x4600, var, True)
            self.width, self.height, _, _, self.xoffset, self.yoffset = struct.unpack_from('6I', var, 0)
            fields = struct.unpack_from('12I', var, 32)
            self.channels = [(fields[n], fields[n + 1]) for n in (0, 3, 6)]
            self.memory = mmap.mmap(self.fd, self.stride * virtual_height)
        except BaseException:
            os.close(self.fd)
            raise

    def show(self, image):
        import numpy as np
        image = image.resize((self.width, self.height))
        rgb = np.asarray(image, dtype=np.uint32)
        packed = np.zeros((self.height, self.width), dtype=np.uint32)
        for index, (offset, length) in enumerate(self.channels):
            packed |= (rgb[:, :, index] >> (8 - length)) << offset
        dtype = '<u2' if self.bits == 16 else '<u4'
        data = packed.astype(dtype).view(np.uint8).reshape(self.height, -1)
        target = np.ndarray((self.height, self.stride), np.uint8, buffer=self.memory,
                            offset=self.yoffset * self.stride)
        start = self.xoffset * (self.bits // 8)
        target[:, start:start + data.shape[1]] = data

    def close(self):
        self.memory.close()
        os.close(self.fd)


def inference_command(root=ROOT):
    """Prefer a real model; otherwise offer the explicitly labeled offline demo."""
    manifest = root / 'data/field/cm4/manifest.csv'
    model = root / 'models/cm4_tcn.pt'
    output = root / 'data/field/cm4/independent-inference.json'
    if not (manifest.exists() and model.exists()):
        manifest = root / 'data/field/install-check/manifest.csv'
        model = manifest.parent / 'tcn.pt'
        output = manifest.parent / 'tcn.inference.json'
    if not manifest.exists() or not model.exists():
        raise RuntimeError('Run the offline check first; no local sample/model available')
    with manifest.open(newline='') as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise RuntimeError('Capture manifest has no sessions')
    row = rows[-1]
    if not all(row.get(key) for key in ('pcap', 'bssid', 'client_mac')):
        raise RuntimeError('Capture manifest requires pcap, bssid, and client_mac')
    pcap = manifest.parent / row['pcap']
    if not pcap.is_file():
        raise RuntimeError('Manifest capture is missing from local storage')
    return [sys.executable, '-m', 'infer.field_inference', '--pcap', str(pcap),
            '--bssid', row['bssid'], '--client-mac', row['client_mac'], '--checkpoint', str(model),
            '--device', 'cpu', '--out', str(output)]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--framebuffer', default='/dev/fb0')
    p.add_argument('--snapshot', type=Path)
    p.add_argument('--once', action='store_true')
    args = p.parse_args()
    if args.snapshot:
        args.snapshot.parent.mkdir(parents=True, exist_ok=True)
        render(status()).save(args.snapshot)
        if args.once:
            return
    framebuffer = Framebuffer(args.framebuffer)
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    joystick = None
    child = None
    logfile = None
    try:
        if Path('/dev/input/js0').exists():
            joystick = os.open('/dev/input/js0', os.O_RDONLY | os.O_NONBLOCK)
        message = 'Ready'
        while running:
            if child and child.poll() is not None:
                message = 'Completed' if child.returncode == 0 else 'Failed; see dashboard.log'
                child = None
                logfile.close();logfile = None
            framebuffer.show(render(status(), message, busy=child is not None))
            if args.once:
                break
            action = None
            if joystick is not None and select.select([joystick], [], [], 0.2)[0]:
                event = os.read(joystick, 8)
                if len(event) == 8:
                    _, value, kind, number = struct.unpack('IhBB', event)
                    if kind == 1 and value == 1:
                        action = {0: 'check', 1: 'quit', 2: 'infer'}.get(number)
            else:
                time.sleep(0.2)
            if action == 'quit':
                running = False
            elif action in ('check', 'infer') and child is None:
                try:
                    command = [sys.executable, str(ROOT / 'scripts/verify_install.py')] if action == 'check' else inference_command()
                    logfile = (ROOT / 'data/field/dashboard.log').open('a')
                    child = subprocess.Popen(command, cwd=ROOT, stdout=logfile, stderr=subprocess.STDOUT,
                                             env={**os.environ, 'OMP_NUM_THREADS': '2'})
                    message = 'Checking runtime' if action == 'check' else 'Classifying local sample'
                except (OSError, RuntimeError) as exc:
                    message = str(exc)
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill();child.wait()
        if logfile is not None:
            logfile.close()
        if joystick is not None:
            os.close(joystick)
        framebuffer.close()


if __name__ == '__main__':
    main()
