#!/usr/bin/env python3
"""Run on Lakka after deployment to install a local dashboard launcher."""
import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--start', action='store_true', help='Show dashboard now, temporarily replacing RetroArch')
    args = p.parse_args()
    if os.geteuid() != 0 or not Path('/storage/.config/system.d').is_dir():
        p.error('run as root on Lakka')
    if any(c in str(ROOT) for c in (' ', '\n', '%')):
        p.error('install path must not contain spaces, newlines, or percent signs')
    launcher_core = Path('/storage/cores/bash_launcher_libretro.so')
    if not launcher_core.exists():
        p.error('Bash Launcher core is required at /storage/cores/bash_launcher_libretro.so')
    (ROOT / 'data/field').mkdir(parents=True, exist_ok=True)
    unit = Path('/storage/.config/system.d/wifi-classifier.service')
    unit.write_text(f'''[Unit]
Description=Local Wi-Fi Classifier Dashboard
Conflicts=retroarch.service
After=retroarch.service
ConditionPathExists=/dev/fb0

[Service]
Type=simple
WorkingDirectory={ROOT}
Environment=OMP_NUM_THREADS=2
ExecStart={ROOT}/.venv/bin/python {ROOT}/scripts/cm4_dashboard.py
ExecStopPost=/usr/bin/systemctl --no-block start retroarch.service
TimeoutStopSec=10

''')
    launcher = Path('/storage/roms/tools/WiFiClassifier.sh')
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text('#!/bin/sh\nsystemctl --no-block start wifi-classifier.service\n')
    launcher.chmod(0o755)
    playlist = Path('/storage/playlists/Wi-Fi Classifier.lpl')
    playlist.write_text(json.dumps({
        'version': '1.5', 'default_core_path': str(launcher_core),
        'default_core_name': 'Bash Launcher', 'label_display_mode': 0,
        'right_thumbnail_mode': 0, 'left_thumbnail_mode': 0,
        'sort_mode': 0, 'items': [{
            'path': str(launcher), 'label': 'Wi-Fi Classifier',
            'core_path': str(launcher_core), 'core_name': 'Bash Launcher',
            'crc32': '00000000|crc', 'db_name': 'Wi-Fi Classifier.lpl',
        }],
    }, indent=2))
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    if args.start:
        subprocess.run(['systemctl', 'start', 'wifi-classifier.service'], check=True)
    print(json.dumps({'service': str(unit), 'playlist': str(playlist), 'started': args.start}))


if __name__ == '__main__':
    main()
