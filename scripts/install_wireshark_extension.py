#!/usr/bin/env python3
"""Install or uninstall the 802.11 Raw Application Classifier Wireshark Extension.

Installs:
  1. Lua Plugin (Postdissector & GUI Menu Tools) -> ~/.local/lib/wireshark/plugins/
  2. Extcap Plugin (Capture Interface)          -> ~/.local/lib/wireshark/extcap/
  3. Pre-exported model weights                 -> models/active_model.json
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
LUA_SRC = ROOT / "wireshark" / "wifi_app_classifier.lua"
EXTCAP_SRC = ROOT / "wireshark" / "extcap" / "wifi_app_extcap.py"
HELPER_SRC = ROOT / "wireshark" / "wifi_app_helper.py"

HOME = Path.home()
PLUGIN_DIRS = [
    HOME / ".local" / "lib" / "wireshark" / "plugins",
    HOME / ".config" / "wireshark" / "plugins",
]
EXTCAP_DIR = HOME / ".local" / "lib" / "wireshark" / "extcap"


def install() -> None:
    print("=" * 70)
    print("Installing 802.11 Application Classifier Wireshark Extension")
    print("=" * 70)

    # 1. Export active model weights if not already present
    from wireshark.wifi_app_helper import export_model_weights
    weights = export_model_weights()
    print(f"✓ Model weights exported to: {weights}")

    # 2. Link Lua Plugin
    for pdir in PLUGIN_DIRS:
        pdir.mkdir(parents=True, exist_ok=True)
        target = pdir / "wifi_app_classifier.lua"
        if target.is_symlink() or target.exists():
            target.unlink()
        target.symlink_to(LUA_SRC)
        print(f"✓ Linked Lua Plugin -> {target}")

    # 3. Link Extcap Interface
    EXTCAP_DIR.mkdir(parents=True, exist_ok=True)
    extcap_target = EXTCAP_DIR / "wifi_app_capture"
    if extcap_target.is_symlink() or extcap_target.exists():
        extcap_target.unlink()
    extcap_target.symlink_to(EXTCAP_SRC)
    extcap_target.chmod(0o755)
    print(f"✓ Linked Extcap Tool -> {extcap_target}")

    # 4. Verify with tshark
    tshark = shutil.which("tshark") or "/opt/homebrew/bin/tshark"
    if os.path.exists(tshark):
        print("\nVerifying extension in TShark / Wireshark...")
        sample_pcap = ROOT / "data" / "field" / "install-check" / "synthetic-16-fixture_small-0.pcap"
        cmd = [tshark, "-r", str(sample_pcap), "-c", "1", "-T", "fields",
               "-e", "frame.number", "-e", "wifi_app.direction", "-e", "wifi_app.prediction", "-e", "wifi_app.confidence"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if "[WiFi-App]" in res.stdout + res.stderr or "fixture" in res.stdout:
            print("✓ TShark verification passed successfully!")
            print(f"  Sample dissection: {res.stdout.strip()}")
        else:
            print(f"⚠️  Verification output:\n{res.stdout}\n{res.stderr}")
    else:
        print("Note: tshark not found in PATH; restart Wireshark to load the extension.")

    print("\n" + "=" * 70)
    print("Wireshark Extension Installation Complete!")
    print("Wireshark features active:")
    print("  • Display filter: 'wifi_app', 'wifi_app.prediction', 'wifi_app.confidence'")
    print("  • Tools menu: Tools -> Wi-Fi App Classifier -> [Capture / BSSID / Audit]")
    print("  • Extcap Interface: '802.11 Application Classifier Live Capture'")
    print("=" * 70)


def uninstall() -> None:
    print("Uninstalling Wireshark Extension...")
    for pdir in PLUGIN_DIRS:
        target = pdir / "wifi_app_classifier.lua"
        if target.is_symlink() or target.exists():
            target.unlink()
            print(f"✓ Removed {target}")
    extcap_target = EXTCAP_DIR / "wifi_app_capture"
    if extcap_target.is_symlink() or extcap_target.exists():
        extcap_target.unlink()
        print(f"✓ Removed {extcap_target}")
    print("Uninstall complete.")


def status() -> None:
    print("Wireshark Extension Status:")
    for pdir in PLUGIN_DIRS:
        target = pdir / "wifi_app_classifier.lua"
        exists = target.exists() or target.is_symlink()
        print(f"  • Lua plugin at {target}: {'INSTALLED' if exists else 'NOT INSTALLED'}")
    extcap_target = EXTCAP_DIR / "wifi_app_capture"
    print(f"  • Extcap tool at {extcap_target}: {'INSTALLED' if extcap_target.exists() else 'NOT INSTALLED'}")
    weights = ROOT / "models" / "active_model.json"
    print(f"  • Model weights at {weights}: {'EXISTS' if weights.exists() else 'MISSING'}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--uninstall", action="store_true", help="Remove extension symlinks")
    p.add_argument("--status", action="store_true", help="Check installation status")
    args = p.parse_args()

    if args.uninstall:
        uninstall()
    elif args.status:
        status()
    else:
        install()


if __name__ == "__main__":
    main()
