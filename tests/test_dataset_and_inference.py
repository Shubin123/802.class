from __future__ import annotations

import csv
from pathlib import Path

import numpy as np
import pytest

from wifi_app.contract import FEATURE_COLUMNS
from wifi_app.dataset import build_field_dataset
from wifi_app.models import TCNConfig, build_tcn
from wifi_app.training import (
    export_tcn_onnx,
    grouped_split_indices,
    load_field_dataset,
    save_bundle,
    train_logistic_baseline,
    train_tcn,
)

from .helpers import BSSID, CLIENT_A, CLIENT_B, scoped_frames


def _write_manifest(path: Path) -> None:
    rows = []
    for label in ("app_a", "app_b"):
        for ordinal in range(2):
            rows.append({
                "pcap": f"{label}_{ordinal}.pcapng",
                "bssid": BSSID,
                "label": label,
                "session_id": f"{label}-session-{ordinal}",
                "client_mac": CLIENT_A if ordinal == 0 else CLIENT_B,
                "device_id": f"device-{ordinal}",
            })
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def test_manifest_dataset_and_grouped_split(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.csv"
    _write_manifest(manifest)

    def parser(path: Path, bssid: str):
        # Labels receive distinct frame sizes in this fixture; actual performance
        # is irrelevant—the test checks the build/split contract.
        frames = scoped_frames(count=8, client=CLIENT_A if "_0" in path.stem else CLIENT_B)
        if path.stem.startswith("app_b"):
            for index, frame in enumerate(frames):
                observation = frame.observation
                frames[index] = type(frame)(
                    observation=type(observation)(**{**observation.__dict__, "mpdu_len": 600, "payload_len": 550}),
                    bssid=frame.bssid,
                    client_mac=frame.client_mac,
                    direction=frame.direction,
                )
        return frames, {"accepted": len(frames)}

    out = tmp_path / "dataset.parquet"
    report = build_field_dataset(manifest, out, window_size=4, stride=4, min_frames=4, parser=parser)
    assert report["samples"] == 8
    arrays = load_field_dataset(out)
    assert arrays.x.shape == (8, len(FEATURE_COLUMNS), 4)
    train_idx, val_idx = grouped_split_indices(arrays, folds=2)
    assert not (set(arrays.groups[train_idx]) & set(arrays.groups[val_idx]))
    assert set(arrays.y[train_idx]) == set(arrays.y[val_idx]) == {0, 1}


def test_grouped_training_and_onnx_export_smoke(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.csv"
    _write_manifest(manifest)

    def parser(path: Path, bssid: str):
        frames = scoped_frames(count=8, client=CLIENT_A if "_0" in path.stem else CLIENT_B)
        # Make the synthetic labels separable enough that both fitting paths see
        # a legitimate two-class grouped partition. This is a plumbing smoke
        # test, not a claimed accuracy benchmark.
        if path.stem.startswith("app_b"):
            for index, frame in enumerate(frames):
                obs = frame.observation
                frames[index] = type(frame)(
                    observation=type(obs)(**{**obs.__dict__, "mpdu_len": 600, "payload_len": 550}),
                    bssid=frame.bssid, client_mac=frame.client_mac, direction=frame.direction,
                )
        return frames, {"accepted": len(frames)}

    data = tmp_path / "dataset.parquet"
    build_field_dataset(manifest, data, window_size=4, stride=4, min_frames=4, parser=parser)
    arrays = load_field_dataset(data)
    train_idx, val_idx = grouped_split_indices(arrays, folds=2)
    baseline, baseline_report = train_logistic_baseline(arrays, train_idx, val_idx)
    assert baseline_report["validation"]["macro_f1"] >= 0.0
    bundle, report = train_tcn(
        arrays, train_idx, val_idx, width=8, blocks=1, dropout=0.0,
        epochs=1, batch_size=4, patience=1, device="cpu",
    )
    checkpoint, report_path = save_bundle(bundle, report, tmp_path / "field.pt")
    assert checkpoint.exists() and report_path.exists()
    exported = export_tcn_onnx(bundle, tmp_path / "field.onnx")
    assert exported.exists() and exported.stat().st_size > 0


def _write_monitor_pcap(path: Path) -> None:
    scapy = pytest.importorskip("scapy.all")
    RadioTap, Dot11, Dot11QoS, Raw, wrpcap = (
        scapy.RadioTap,
        scapy.Dot11,
        scapy.Dot11QoS,
        scapy.Raw,
        scapy.wrpcap,
    )
    packets = []
    for index in range(8):
        client = CLIENT_A if index < 4 else CLIENT_B
        if index % 2 == 0:
            dot11 = Dot11(type=2, subtype=8, FCfield=0x41, addr1=BSSID, addr2=client, addr3="02:00:00:00:00:aa", SC=(index + 1) << 4)
        else:
            dot11 = Dot11(type=2, subtype=8, FCfield=0x42, addr1=client, addr2=BSSID, addr3="02:00:00:00:00:aa", SC=(index + 1) << 4)
        packet = RadioTap() / dot11 / Dot11QoS(TID=3) / Raw(b"x" * (40 + index))
        packet.time = 1.0 + index * 0.1
        packets.append(packet)
    # A valid-looking frame for another BSSID proves the parser does not use
    # addr3 as a generic MAC-anywhere filter.
    foreign = RadioTap() / Dot11(type=2, subtype=8, FCfield=0x41, addr1="02:00:00:00:00:02", addr2=CLIENT_A, addr3=BSSID) / Dot11QoS(TID=3) / Raw(b"foreign")
    foreign.time = 2.0
    packets.append(foreign)
    wrpcap(str(path), packets)


def test_pcap_to_bssid_scoped_model_inference_round_trip(tmp_path: Path) -> None:
    pcap = tmp_path / "capture.pcapng"
    _write_monitor_pcap(pcap)
    from infer.field_inference import infer_capture

    config = TCNConfig(in_channels=len(FEATURE_COLUMNS), num_classes=2, width=8, blocks=1, dropout=0.0)
    model = build_tcn(config)
    bundle = {
        "kind": "field-tcn-v1",
        "schema_version": "80211-metadata-v1",
        "feature_columns": list(FEATURE_COLUMNS),
        "window_size": 4,
        "labels": ["app_a", "app_b"],
        "model_config": config.__dict__,
        "state_dict": model.state_dict(),
        "normalizer": {"mean": np.zeros(len(FEATURE_COLUMNS), dtype=np.float32), "std": np.ones(len(FEATURE_COLUMNS), dtype=np.float32)},
        "unknown_threshold": 0.0,
        "preprocessing": {"min_frames": 2, "stride": 4, "require_protected": True, "deduplicate_retries": True},
    }
    result = infer_capture(pcap, BSSID, bundle, device="cpu")
    assert result["status"] == "ok"
    assert {item["client_mac"] for item in result["sessions"]} == {CLIENT_A, CLIENT_B}
    assert result["capture_quality"]["scope_counts"]["different_bssid"] == 1
    assert all(item["prediction"] in {"app_a", "app_b"} for item in result["windows"])
