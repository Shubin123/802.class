#!/usr/bin/env python3
"""Wireshark bridge helper for the Raw 802.11 Application Classifier.

Provides CLI commands invoked by the Wireshark Lua extension and Extcap interface:
  --status                     Environment, model catalog, CM4 status
  --discover-bssids <pcap>     List beacon-observed BSSIDs, SSIDs, and channels
  --classify-capture <pcap>    Run BSSID-scoped inference and write session cache
  --export-model-weights       Export baseline weights to JSON for high-speed Lua dissection
  --self-test                  Validate Scapy, PyTorch, CCMP/GCMP pipeline, and model loading
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"

# Re-exec with repo virtualenv if available and not currently active
if VENV_PYTHON.exists() and sys.executable != str(VENV_PYTHON) and not os.environ.get("_WIFI_APP_REEXEC"):
    os.environ["_WIFI_APP_REEXEC"] = "1"
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON)] + sys.argv)

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wifi_app.capture import discover_bssids, scope_pcap
from wifi_app.contract import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION, normalize_mac
from infer.field_inference import infer_capture, load_bundle


DEFAULT_CACHE_PATH = Path("/tmp/wifi_app_sessions.json")
DEFAULT_WEIGHTS_PATH = ROOT / "models" / "active_model.json"


def find_default_checkpoint(preferred: str = "tcn") -> Path | None:
    """Locate a trained or verified model bundle."""
    candidates = []
    if preferred == "tcn":
        candidates = [
            ROOT / "models" / "field_tcn.pt",
            ROOT / "models" / "tcn.pt",
            ROOT / "data" / "field" / "cm4" / "tcn.pt",
            ROOT / "data" / "field" / "install-check" / "tcn.pt",
            ROOT / "models" / "field_baseline.joblib",
            ROOT / "models" / "baseline.joblib",
            ROOT / "data" / "field" / "install-check" / "baseline.joblib",
        ]
    else:
        candidates = [
            ROOT / "models" / "field_baseline.joblib",
            ROOT / "models" / "baseline.joblib",
            ROOT / "data" / "field" / "cm4" / "baseline.joblib",
            ROOT / "data" / "field" / "install-check" / "baseline.joblib",
            ROOT / "models" / "field_tcn.pt",
            ROOT / "models" / "tcn.pt",
            ROOT / "data" / "field" / "install-check" / "tcn.pt",
        ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def export_model_weights(checkpoint_path: Path | None = None, out_path: Path | None = None) -> Path:
    """Export logistic baseline weights to JSON for real-time Lua evaluation."""
    import joblib
    import numpy as np

    if checkpoint_path is None:
        # Prefer a joblib baseline
        checkpoint_path = (
            ROOT / "models" / "field_baseline.joblib"
            if (ROOT / "models" / "field_baseline.joblib").exists()
            else ROOT / "data" / "field" / "install-check" / "baseline.joblib"
        )
    if not checkpoint_path.exists():
        # Generate one via offline verification
        from scripts.verify_install import main as run_verify
        run_verify()
        checkpoint_path = ROOT / "data" / "field" / "install-check" / "baseline.joblib"

    bundle = joblib.load(checkpoint_path)
    if bundle.get("kind") != "field-logistic-baseline-v1":
        raise ValueError(f"checkpoint {checkpoint_path} is not a field-logistic-baseline-v1 bundle")

    clf = bundle["classifier"]
    coef = clf.coef_
    intercept = clf.intercept_
    classes = [int(c) for c in clf.classes_]
    labels = list(bundle["labels"])

    data = {
        "kind": "field-logistic-baseline-v1",
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_columns": list(FEATURE_COLUMNS),
        "window_size": int(bundle["window_size"]),
        "labels": labels,
        "classes": classes,
        "coefficients": coef.tolist(),
        "intercepts": intercept.tolist(),
        "is_binary": bool(len(classes) == 2 and coef.shape[0] == 1),
        "preprocessing": bundle.get("preprocessing", {}),
        "exported_at": time.time(),
    }

    target = out_path or DEFAULT_WEIGHTS_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return target


def cmd_status() -> dict[str, Any]:
    """Report local environment, model catalog, and CM4 reachability."""
    tcn_model = find_default_checkpoint("tcn")
    base_model = find_default_checkpoint("baseline")

    cm4_online = False
    cm4_info = "unreachable"
    try:
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2", "root@192.168.1.96", "uname -r; iw dev wlan0 link"],
            capture_output=True, text=True, timeout=3
        )
        if r.returncode == 0:
            cm4_online = True
            first_line = r.stdout.splitlines()[0] if r.stdout.splitlines() else "Linux"
            cm4_info = f"Online (Kernel {first_line})"
    except Exception:
        pass

    import torch
    status = {
        "status": "ok",
        "python": sys.executable,
        "python_version": sys.version.split()[0],
        "torch_version": torch.__version__,
        "torch_device": "mps" if torch.backends.mps.is_available() else ("cuda" if torch.cuda.is_available() else "cpu"),
        "models": {
            "tcn": str(tcn_model) if tcn_model else None,
            "baseline": str(base_model) if base_model else None,
            "weights_json": str(DEFAULT_WEIGHTS_PATH) if DEFAULT_WEIGHTS_PATH.exists() else None,
        },
        "cm4_dut": {
            "host": "root@192.168.1.96",
            "online": cm4_online,
            "details": cm4_info,
        },
        "encryption_support": {
            "wpa2_ccmp": "Supported (8-byte MIC envelope)",
            "wpa3_sae_ccmp": "Supported (8-byte MIC envelope)",
            "wpa3_sae_gcmp": "Supported (16-byte MIC envelope)",
            "live_status": "DUT connected via WPA2-PSK (CCMP); WPA3 requires SAE test AP",
        },
        "wireshark": {
            "lua_cache": str(DEFAULT_CACHE_PATH),
            "lua_cache_exists": DEFAULT_CACHE_PATH.exists(),
        }
    }
    return status


def cmd_discover_bssids(pcap_path: str | Path) -> list[dict[str, Any]]:
    """Discover beacon-advertised BSSIDs in capture."""
    pcap = Path(pcap_path)
    if not pcap.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap}")
    items = discover_bssids(pcap)
    return [
        {
            "bssid": item.bssid,
            "ssid": item.ssid or "<hidden>",
            "beacons": item.beacon_count,
            "channels_mhz": list(item.channels_mhz),
        }
        for item in items
    ]


def cmd_classify_capture(
    pcap_path: str | Path,
    bssid: str | None = None,
    checkpoint: str | Path | None = None,
    threshold: float = 0.50,
    out_cache: str | Path | None = None,
) -> dict[str, Any]:
    """Run full BSSID-scoped inference and output session cache for Wireshark."""
    pcap = Path(pcap_path).resolve()
    if not pcap.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap}")

    # Auto-discover target BSSID if not explicitly provided
    if not bssid:
        discovered = discover_bssids(pcap)
        if discovered:
            # Pick the BSSID with the most beacons
            best = max(discovered, key=lambda x: x.beacon_count)
            bssid = best.bssid
        else:
            # Fallback: inspect raw data frames in capture to find common BSSID
            from wifi_app.capture import iter_pcap_observations
            bssid_counts: dict[str, int] = {}
            for obs in iter_pcap_observations(pcap):
                if obs.to_ds and obs.addr1:
                    bssid_counts[obs.addr1] = bssid_counts.get(obs.addr1, 0) + 1
                elif obs.from_ds and obs.addr2:
                    bssid_counts[obs.addr2] = bssid_counts.get(obs.addr2, 0) + 1
            if not bssid_counts:
                raise ValueError("No infrastructure BSSID found in capture (beacons or DS frames)")
            bssid = max(bssid_counts.items(), key=lambda kv: kv[1])[0]

    bssid = normalize_mac(bssid)
    assert bssid is not None

    model_path = Path(checkpoint) if checkpoint else find_default_checkpoint("tcn")
    if not model_path or not model_path.exists():
        # Ensure default baseline weights exist
        export_model_weights()
        model_path = find_default_checkpoint("tcn") or find_default_checkpoint("baseline")
        if not model_path or not model_path.exists():
            raise FileNotFoundError("No classifier model checkpoint found. Run verify_install.py first.")

    bundle = load_bundle(model_path)
    bundle["unknown_threshold"] = float(threshold)

    result = infer_capture(pcap, bssid, bundle, device="cpu")

    # Build per-window timestamp ranges for fast Wireshark packet matching
    cache_windows = []
    for w in result.get("windows", []):
        cache_windows.append({
            "client_mac": w["client_mac"],
            "start_time": float(w["start_timestamp"]),
            "end_time": float(w["end_timestamp"]),
            "prediction": w["prediction"],
            "known_prediction": w["known_prediction"],
            "confidence": float(w["confidence"]),
            "valid_frames": int(w["valid_frames"]),
            "session_id": w["session_id"],
        })

    cache_data = {
        "pcap": str(pcap),
        "bssid": bssid,
        "model_path": str(model_path),
        "model_kind": bundle.get("kind"),
        "labels": list(bundle.get("labels", [])),
        "threshold": float(threshold),
        "status": result.get("status"),
        "capture_quality": result.get("capture_quality", {}),
        "sessions": result.get("sessions", []),
        "windows": cache_windows,
        "analyzed_at": time.time(),
    }

    cache_file = Path(out_cache) if out_cache else DEFAULT_CACHE_PATH
    cache_file.write_text(json.dumps(cache_data, indent=2), encoding="utf-8")
    result["cache_file"] = str(cache_file)
    return result


def format_capture_report(result: dict[str, Any]) -> str:
    """Format human-readable terminal/Wireshark TextWindow report."""
    lines = [
        "=" * 78,
        "          802.11 Raw Application Classifier — Inference Report",
        "=" * 78,
        f"Capture File : {result.get('pcap', 'N/A')}",
        f"Target BSSID : {result.get('bssid', 'N/A')}",
        f"Model Kind   : {result.get('model_kind', 'N/A')}",
        f"Status       : {result.get('status', 'N/A')}",
        "-" * 78,
        "Client Sessions Identified:",
    ]
    sessions = result.get("sessions", [])
    if not sessions:
        lines.append("  (No client sessions met the minimum frame criteria)")
    else:
        for s in sessions:
            pred = s.get("prediction", "N/A")
            conf = s.get("confidence", 0.0) * 100
            frames = s.get("frames", 0)
            windows = s.get("windows", 0)
            client = s.get("client_mac", "N/A")
            lines.append(
                f"  • Client {client} | Windows: {windows:2d} | Frames: {frames:3d} | "
                f"Prediction: {pred} ({conf:.1f}%)"
            )

    windows = result.get("windows", [])
    if windows:
        lines.append("-" * 78)
        lines.append(f"Window Breakdown ({len(windows)} total observation windows):")
        for i, w in enumerate(windows[:12]):
            st = w.get("start_time", w.get("start_timestamp", 0.0))
            et = w.get("end_time", w.get("end_timestamp", 0.0))
            lines.append(
                f"  [{i+1:02d}] {w['client_mac']} | {st:.2f}s - {et:.2f}s | "
                f"{w['prediction']} (conf: {w['confidence']*100:.1f}%, frames: {w['valid_frames']})"
            )
        if len(windows) > 12:
            lines.append(f"  ... and {len(windows) - 12} more windows.")

    lines.append("=" * 78)
    return "\n".join(lines)


def cmd_test_capture(count: int = 20) -> dict[str, Any]:
    """Test live extcap streaming, Wireshark FIFO ingestion, and real-time classification."""
    import tempfile
    extcap = ROOT / "wireshark" / "extcap" / "wifi_app_extcap.py"
    lua_script = ROOT / "wireshark" / "wifi_app_classifier.lua"
    tshark = shutil.which("tshark") or "/opt/homebrew/bin/tshark"
    if not os.path.exists(tshark):
        raise FileNotFoundError(f"tshark not found: {tshark}")

    fifo_dir = Path(tempfile.mkdtemp(prefix="wifi_app_test_"))
    fifo_path = fifo_dir / "capture.fifo"
    os.mkfifo(fifo_path)

    try:
        tshark_cmd = [
            tshark,
            "-X", f"lua_script:{lua_script}",
            "-i", str(fifo_path),
            "-c", str(count),
            "-T", "fields",
            "-e", "frame.number",
            "-e", "wlan.fc.type",
            "-e", "wlan.sa",
            "-e", "wifi_app.direction",
            "-e", "wifi_app.prediction",
            "-e", "wifi_app.confidence",
        ]
        tshark_proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(0.3)

        extcap_cmd = [
            sys.executable,
            str(extcap),
            "--extcap-interface", "wifi_app_demo",
            "--capture",
            "--fifo", str(fifo_path),
            "--pace", "1.0",
        ]
        extcap_proc = subprocess.Popen(extcap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        stdout, stderr = tshark_proc.communicate(timeout=10)
        if extcap_proc.poll() is None:
            extcap_proc.terminate()

        lines = [l.strip() for l in stdout.splitlines() if l.strip() and not l.startswith("[")]
        data_frames = 0
        classified = 0
        sample_predictions = []
        for l in lines:
            parts = l.split("\t")
            if len(parts) >= 2 and parts[1] == "2":
                data_frames += 1
                if len(parts) >= 5 and parts[4]:
                    classified += 1
                    sample_predictions.append({
                        "frame": parts[0],
                        "pred": parts[4],
                        "conf": parts[5] if len(parts) > 5 else "0"
                    })

        result = {
            "status": "passed" if len(lines) >= count else "partial",
            "packets_captured": len(lines),
            "data_frames": data_frames,
            "classified_frames": classified,
            "sample_predictions": sample_predictions[:5],
        }
        return result
    finally:
        if fifo_path.exists():
            os.remove(fifo_path)
        if fifo_dir.exists():
            shutil.rmtree(fifo_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", action="store_true", help="Print environment and model status")
    parser.add_argument("--test-capture", action="store_true", help="Test live extcap FIFO capture and classification")
    parser.add_argument("--discover-bssids", metavar="PCAP", help="Discover BSSIDs in a capture file")
    parser.add_argument("--classify-capture", metavar="PCAP", help="Classify all client windows in capture")
    parser.add_argument("--bssid", help="Target AP BSSID MAC")
    parser.add_argument("--checkpoint", help="Path to .pt or .joblib model bundle")
    parser.add_argument("--threshold", type=float, default=0.50, help="Confidence threshold for unknown rejection")
    parser.add_argument("--export-model-weights", action="store_true", help="Export baseline weights for Lua dissector")
    parser.add_argument("--out", type=Path, help="Output destination path")
    parser.add_argument("--json", action="store_true", help="Force raw JSON output")
    parser.add_argument("--self-test", action="store_true", help="Run synthetic self-test")
    args = parser.parse_args()

    if args.status:
        data = cmd_status()
        print(json.dumps(data, indent=2))
        return

    if args.test_capture:
        result = cmd_test_capture()
        print(json.dumps(result, indent=2))
        return

    if args.export_model_weights:
        out = export_model_weights(checkpoint_path=Path(args.checkpoint) if args.checkpoint else None, out_path=args.out)
        print(json.dumps({"exported_weights": str(out), "size_bytes": out.stat().st_size}, indent=2))
        return

    if args.discover_bssids:
        items = cmd_discover_bssids(args.discover_bssids)
        if args.json:
            print(json.dumps(items, indent=2))
        else:
            print("=" * 60)
            print(f"Discovered BSSIDs in: {args.discover_bssids}")
            print("=" * 60)
            if not items:
                print("No beacons observed.")
            for it in items:
                chans = ", ".join(f"{c}MHz" for c in it["channels_mhz"]) or "N/A"
                print(f"BSSID: {it['bssid']} | SSID: {it['ssid']:<20} | Beacons: {it['beacons']} | Channels: {chans}")
            print("=" * 60)
        return

    if args.classify_capture:
        res = cmd_classify_capture(
            args.classify_capture,
            bssid=args.bssid,
            checkpoint=args.checkpoint,
            threshold=args.threshold,
            out_cache=args.out,
        )
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(format_capture_report(res))
        return

    if args.self_test:
        from scripts.verify_install import main as run_verify
        run_verify()
        export_model_weights()
        print(json.dumps({"self_test": "passed", "timestamp": time.time()}, indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()
