#!/usr/bin/env python3
"""BSSID-scoped application inference over a raw monitor-mode capture.

This is separate from ``infer/inference.py``, which remains the legacy
TLS/hwsim experiment path.  Output labels mean "this client observation window
is consistent with a known label", not a claim that every packet belongs to one
application.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wifi_app.capture import CaptureDependencyError, discover_bssids, scope_pcap
from wifi_app.contract import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION, feature_matrix, sessionize, window_sessions
from wifi_app.models import build_tcn
from wifi_app.training import aggregate_windows, normalize_windows


def load_bundle(path: str | Path) -> dict[str, Any]:
    model_path = Path(path)
    if not model_path.exists():
        raise FileNotFoundError(model_path)
    if model_path.suffix.lower() in {".joblib", ".pkl", ".pickle"}:
        bundle = joblib.load(model_path)
    else:
        # Checkpoints are locally produced artifacts, not untrusted downloads.
        bundle = torch.load(model_path, map_location="cpu", weights_only=False)
    if not isinstance(bundle, dict) or not str(bundle.get("kind", "")).startswith("field-"):
        raise ValueError("checkpoint is not a field-pipeline bundle; legacy checkpoints are intentionally unsupported")
    if bundle.get("schema_version") != FEATURE_SCHEMA_VERSION:
        raise ValueError(f"checkpoint schema mismatch: {bundle.get('schema_version')!r}")
    if tuple(bundle.get("feature_columns", ())) != FEATURE_COLUMNS:
        raise ValueError("checkpoint feature order does not match the field contract")
    return bundle


def predict(bundle: dict[str, Any], matrices: np.ndarray, valid_frames: np.ndarray, device: str | None) -> tuple[np.ndarray, np.ndarray]:
    """Return known-class indices and confidence for fixed field windows."""
    if bundle["kind"] == "field-logistic-baseline-v1":
        features = aggregate_windows(matrices, valid_frames)
        classifier = bundle["classifier"]
        probabilities = classifier.predict_proba(features)
        return probabilities.argmax(axis=1), probabilities.max(axis=1)
    if bundle["kind"] != "field-tcn-v1":
        raise ValueError(f"unsupported field bundle kind: {bundle['kind']}")
    selected_device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
    normalizer = bundle["normalizer"]
    x = normalize_windows(
        matrices,
        valid_frames,
        np.asarray(normalizer["mean"], dtype=np.float32),
        np.asarray(normalizer["std"], dtype=np.float32),
    )
    model = build_tcn(bundle["model_config"]).to(selected_device)
    model.load_state_dict(bundle["state_dict"])
    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(x).to(selected_device))
        probabilities = torch.softmax(logits, dim=1).cpu().numpy()
    return probabilities.argmax(axis=1), probabilities.max(axis=1)


def infer_capture(
    pcap: str | Path,
    bssid: str,
    bundle: dict[str, Any],
    *,
    client_mac: str | None = None,
    include_unprotected: bool | None = None,
    keep_retries: bool | None = None,
    min_frames: int | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Run the complete offline field path. Kept callable for E2E tests."""
    pre = dict(bundle.get("preprocessing", {}))
    require_protected = not bool(include_unprotected) if include_unprotected is not None else bool(pre.get("require_protected", True))
    deduplicate_retries = not bool(keep_retries) if keep_retries is not None else bool(pre.get("deduplicate_retries", True))
    window_size = int(bundle["window_size"])
    selected_min_frames = int(min_frames if min_frames is not None else pre.get("min_frames", min(16, window_size)))
    stride = int(pre.get("stride", max(1, window_size // 2)))
    idle_timeout = float(pre.get("idle_timeout_seconds", 15.0))
    scoped, scope_counts = scope_pcap(pcap, bssid, client_mac=client_mac)
    scoped_before_protection = len(scoped)
    if require_protected:
        scoped = [frame for frame in scoped if frame.observation.protected]
    sessions, session_stats = sessionize(
        scoped,
        capture_id=Path(pcap).stem,
        idle_timeout_seconds=idle_timeout,
        deduplicate_retries=deduplicate_retries,
    )
    windows = list(window_sessions(sessions, window_size=window_size, stride=stride, min_frames=selected_min_frames))
    result: dict[str, Any] = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "pcap": str(Path(pcap)),
        "bssid": bssid.lower(),
        "model_kind": bundle["kind"],
        "window_size": window_size,
        "min_frames": selected_min_frames,
        "preprocessing": {
            "require_protected": require_protected,
            "deduplicate_retries": deduplicate_retries,
            "idle_timeout_seconds": idle_timeout,
        },
        "capture_quality": {
            "scope_counts": scope_counts,
            "bssid_scoped_frames": scoped_before_protection,
            "frames_after_protection_filter": len(scoped),
            "session_stats": session_stats,
        },
        "sessions": [],
    }
    by_session: dict[str, list[int]] = defaultdict(list)
    for index, window in enumerate(windows):
        by_session[window.session_id].append(index)
    if not windows:
        result["status"] = "insufficient_data"
        for session in sessions:
            result["sessions"].append({
                "session_id": session.session_id,
                "client_mac": session.client_mac,
                "start_timestamp": session.start_timestamp,
                "end_timestamp": session.end_timestamp,
                "frames": len(session.frames),
                "status": "insufficient_data",
                "reason": f"fewer than {selected_min_frames} usable frames",
            })
        if not sessions:
            result["status"] = "insufficient_data"
            result["reason"] = "no BSSID-scoped usable client frames"
        return result

    matrices = np.asarray([feature_matrix(window, window_size=window_size) for window in windows], dtype=np.float32)
    valid = np.asarray([window.valid_frames for window in windows], dtype=np.int64)
    indexes, confidence = predict(bundle, matrices, valid, device)
    labels = list(bundle["labels"])
    threshold = float(bundle.get("unknown_threshold", 0.0))
    window_result: list[dict[str, Any]] = []
    for window, index, score in zip(windows, indexes, confidence):
        accepted = float(score) >= threshold
        window_result.append({
            "session_id": window.session_id,
            "client_mac": window.client_mac,
            "start_timestamp": window.start_timestamp,
            "end_timestamp": window.end_timestamp,
            "valid_frames": window.valid_frames,
            "prediction": labels[int(index)] if accepted else "unknown",
            "known_prediction": labels[int(index)],
            "confidence": float(score),
            "threshold": threshold,
        })
    result["windows"] = window_result
    for session in sessions:
        hits = [window_result[index] for index in by_session.get(session.session_id, [])]
        if not hits:
            result["sessions"].append({
                "session_id": session.session_id,
                "client_mac": session.client_mac,
                "frames": len(session.frames),
                "status": "insufficient_data",
                "reason": f"fewer than {selected_min_frames} usable frames",
            })
            continue
        known = [item for item in hits if item["prediction"] != "unknown"]
        if not known:
            prediction = "unknown"
            mean_confidence = float(np.mean([item["confidence"] for item in hits]))
        else:
            vote = Counter(item["prediction"] for item in known)
            prediction = vote.most_common(1)[0][0]
            mean_confidence = float(np.mean([item["confidence"] for item in known if item["prediction"] == prediction]))
        result["sessions"].append({
            "session_id": session.session_id,
            "client_mac": session.client_mac,
            "start_timestamp": session.start_timestamp,
            "end_timestamp": session.end_timestamp,
            "frames": len(session.frames),
            "windows": len(hits),
            "prediction": prediction,
            "confidence": mean_confidence,
            "unknown_windows": len(hits) - len(known),
        })
    result["status"] = "ok"
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Classify BSSID-scoped client windows from a monitor-mode PCAP")
    parser.add_argument("--pcap", required=True, help="Monitor-mode PCAP/PCAPNG")
    parser.add_argument("--bssid", default=None, help="Target AP radio MAC/BSSID, not a generic router MAC")
    parser.add_argument("--checkpoint", default=None, help="Field .pt or .joblib model bundle")
    parser.add_argument("--client-mac", default=None, help="Optional one-client filter")
    parser.add_argument("--include-unprotected", action="store_true", default=None)
    parser.add_argument("--keep-retries", action="store_true", default=None)
    parser.add_argument("--min-frames", type=int, default=None)
    parser.add_argument("--device", default=None)
    parser.add_argument("--out", default=None, help="Write JSON result to this path")
    parser.add_argument("--list-bssids", action="store_true", help="Inspect beacon BSSIDs in the capture before inference")
    parser.add_argument("--require-beacon", action="store_true", help="Fail if the supplied BSSID is not beacon-observed in this capture")
    args = parser.parse_args()
    try:
        discovered = discover_bssids(args.pcap) if (args.list_bssids or args.require_beacon) else []
        if args.list_bssids:
            print(json.dumps({"bssids": [item.__dict__ for item in discovered]}, indent=2))
            if not args.checkpoint:
                return
        if not args.bssid:
            parser.error("--bssid is required for inference")
        if args.require_beacon and args.bssid.lower().replace("-", ":") not in {item.bssid for item in discovered}:
            parser.error("supplied BSSID was not observed in beacons; check radio MAC/channel or omit --require-beacon for a partial capture")
        if not args.checkpoint:
            parser.error("--checkpoint is required unless using --list-bssids only")
        bundle = load_bundle(args.checkpoint)
        result = infer_capture(
            args.pcap, args.bssid, bundle,
            client_mac=args.client_mac,
            include_unprotected=args.include_unprotected,
            keep_retries=args.keep_retries,
            min_frames=args.min_frames,
            device=args.device,
        )
    except (CaptureDependencyError, FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        output = Path(args.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
