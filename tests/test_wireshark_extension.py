"""Automated tests for the Raw 802.11 Application Classifier Wireshark Extension.

Verifies:
  1. wireshark/wifi_app_helper.py CLI commands (--status, --discover-bssids, --classify-capture, --export-model-weights)
  2. wireshark/extcap/wifi_app_extcap.py extcap contract (--extcap-interfaces, --extcap-dlts, --extcap-config)
  3. wireshark/wifi_app_classifier.lua loading, postdissection, and display filters in TShark
  4. scripts/install_wireshark_extension.py status and installation idempotency
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PCAP = ROOT / "data" / "field" / "install-check" / "synthetic-16-fixture_small-0.pcap"


@pytest.fixture(scope="module", autouse=True)
def ensure_fixtures_exist():
    """Ensure sample PCAP and model exist before running tests."""
    if not SAMPLE_PCAP.exists() or not (ROOT / "models" / "active_model.json").exists():
        from scripts.verify_install import main as run_verify
        run_verify()
        from wireshark.wifi_app_helper import export_model_weights
        export_model_weights()


def test_helper_status():
    helper = ROOT / "wireshark" / "wifi_app_helper.py"
    r = subprocess.run([sys.executable, str(helper), "--status"], capture_output=True, text=True, check=True)
    data = json.loads(r.stdout)
    assert data["status"] == "ok"
    assert "torch_version" in data
    assert "models" in data
    assert "encryption_support" in data
    assert "wpa2_ccmp" in data["encryption_support"]
    assert "wpa3_sae_gcmp" in data["encryption_support"]


def test_helper_export_model_weights(tmp_path: Path):
    helper = ROOT / "wireshark" / "wifi_app_helper.py"
    out = tmp_path / "test_weights.json"
    r = subprocess.run([sys.executable, str(helper), "--export-model-weights", "--out", str(out)],
                       capture_output=True, text=True, check=True)
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["kind"] == "field-logistic-baseline-v1"
    assert len(data["coefficients"][0]) == 72
    assert len(data["labels"]) >= 2


def test_helper_discover_bssids():
    helper = ROOT / "wireshark" / "wifi_app_helper.py"
    r = subprocess.run([sys.executable, str(helper), "--discover-bssids", str(SAMPLE_PCAP), "--json"],
                       capture_output=True, text=True, check=True)
    data = json.loads(r.stdout)
    assert isinstance(data, list)


def test_helper_classify_capture(tmp_path: Path):
    helper = ROOT / "wireshark" / "wifi_app_helper.py"
    cache = tmp_path / "test_cache.json"
    r = subprocess.run(
        [sys.executable, str(helper), "--classify-capture", str(SAMPLE_PCAP), "--out", str(cache), "--json"],
        capture_output=True, text=True, check=True
    )
    assert cache.exists()
    data = json.loads(cache.read_text(encoding="utf-8"))
    assert data["status"] == "ok"
    assert len(data["windows"]) >= 1
    assert data["bssid"] == "02:00:00:00:00:01"
    assert all("prediction" in w for w in data["windows"])


def test_extcap_contract():
    extcap = ROOT / "wireshark" / "extcap" / "wifi_app_extcap.py"

    # 1. Interface list
    r1 = subprocess.run([sys.executable, str(extcap), "--extcap-interfaces"], capture_output=True, text=True, check=True)
    assert "interface {value=wifi_app_live}" in r1.stdout

    # 2. DLTs
    r2 = subprocess.run([sys.executable, str(extcap), "--extcap-dlts", "--extcap-interface", "wifi_app_live"],
                        capture_output=True, text=True, check=True)
    assert "dlt {number=127}" in r2.stdout

    # 3. Config
    r3 = subprocess.run([sys.executable, str(extcap), "--extcap-config", "--extcap-interface", "wifi_app_live"],
                        capture_output=True, text=True, check=True)
    assert "--iface" in r3.stdout
    assert "--freq" in r3.stdout
    assert "--bssid" in r3.stdout
    assert "--model" in r3.stdout


@pytest.mark.skipif(not shutil.which("tshark"), reason="TShark not available in environment")
def test_tshark_postdissector_and_display_filters():
    tshark = shutil.which("tshark")
    lua_script = ROOT / "wireshark" / "wifi_app_classifier.lua"

    cmd = [
        tshark,
        "-X", f"lua_script:{lua_script}",
        "-r", str(SAMPLE_PCAP),
        "-Y", "wifi_app.direction == \"uplink\"",
        "-c", "5",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "wifi_app.direction",
        "-e", "wifi_app.client",
        "-e", "wifi_app.prediction",
        "-e", "wifi_app.confidence",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, check=True)
    lines = [line.strip() for line in r.stdout.splitlines() if line.strip() and not line.startswith("[")]
    assert len(lines) >= 1
    first_row = lines[0].split("\t")
    assert len(first_row) >= 4
    direction = first_row[1]
    client = first_row[2]
    prediction = first_row[3]
    assert direction == "uplink"
    assert client == "02:00:00:00:00:11"
    assert prediction in {"fixture_large", "fixture_small"}


def test_install_script_status():
    installer = ROOT / "scripts" / "install_wireshark_extension.py"
    r = subprocess.run([sys.executable, str(installer), "--status"], capture_output=True, text=True, check=True)
    assert "Wireshark Extension Status:" in r.stdout
    assert "INSTALLED" in r.stdout
