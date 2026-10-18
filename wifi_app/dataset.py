"""Manifest-driven real-capture dataset construction for the field pipeline."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import pandas as pd

from .capture import scope_pcap
from .contract import (
    FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
    ScopedFrame,
    feature_matrix,
    normalize_mac,
    sessionize,
    window_sessions,
)


REQUIRED_MANIFEST_COLUMNS = ("pcap", "bssid", "label")
OPTIONAL_GROUP_COLUMNS = (
    "session_id",
    "session",
    "device_id",
    "ap_id",
    "environment_id",
    "collection_day",
    "capture_radio",
    "app_version",
    "security",
)


class ManifestError(ValueError):
    """Raised when a dataset manifest cannot support a valid grouped dataset."""


@dataclass(frozen=True)
class ManifestEntry:
    pcap: Path
    bssid: str
    label: str
    source_session_id: str
    client_mac: str | None
    metadata: dict[str, str]


def _clean(value: object) -> str:
    return "" if value is None else str(value).strip()


def read_manifest(path: str | Path) -> list[ManifestEntry]:
    """Read a real-capture manifest and resolve capture paths relative to it.

    Required columns are deliberately minimal.  ``session_id`` is strongly
    recommended and derived from the row index only as a last resort; callers
    get a warning in the build report when doing so.  ``mac`` remains accepted
    as a compatibility alias for the old two-device collector's client MAC.
    """
    manifest_path = Path(path).resolve()
    if not manifest_path.exists():
        raise FileNotFoundError(manifest_path)
    with manifest_path.open(newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ManifestError("manifest has no data rows")
    columns = set(rows[0])
    missing = set(REQUIRED_MANIFEST_COLUMNS) - columns
    if missing:
        raise ManifestError(f"manifest is missing required columns: {sorted(missing)}")

    entries: list[ManifestEntry] = []
    for index, row in enumerate(rows, start=1):
        try:
            bssid = normalize_mac(_clean(row.get("bssid")))
            client_mac = normalize_mac(_clean(row.get("client_mac") or row.get("mac")))
        except ValueError as exc:
            raise ManifestError(f"row {index}: {exc}") from exc
        label = _clean(row.get("label"))
        pcap_text = _clean(row.get("pcap"))
        if not (bssid and label and pcap_text):
            raise ManifestError(f"row {index}: pcap, bssid, and label must be non-empty")
        pcap = Path(pcap_text)
        if not pcap.is_absolute():
            pcap = (manifest_path.parent / pcap).resolve()
        source_session_id = _clean(row.get("session_id") or row.get("session")) or f"manifest-row-{index:04d}"
        metadata = {key: _clean(row.get(key)) for key in OPTIONAL_GROUP_COLUMNS if key in row}
        metadata["source_manifest_row"] = str(index)
        entries.append(ManifestEntry(pcap, bssid, label, source_session_id, client_mac, metadata))
    return entries


def build_field_dataset(
    manifest_path: str | Path,
    out_path: str | Path,
    *,
    window_size: int = 64,
    stride: int = 32,
    min_frames: int = 16,
    idle_timeout_seconds: float = 15.0,
    require_protected: bool = True,
    deduplicate_retries: bool = True,
    parser: Callable[[Path, str], tuple[list[ScopedFrame], dict[str, int]]] | None = None,
) -> dict[str, object]:
    """Build a versioned per-window Parquet dataset from real monitor captures.

    ``parser`` is injectable for deterministic tests.  Production calls scope
    each PCAP using the same adapter as field inference.
    """
    entries = read_manifest(manifest_path)
    out = Path(out_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    parse = parser or (lambda pcap, bssid: scope_pcap(pcap, bssid))
    records: list[dict[str, object]] = []
    report: dict[str, object] = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "manifest": str(Path(manifest_path).resolve()),
        "window_size": window_size,
        "stride": stride,
        "min_frames": min_frames,
        "idle_timeout_seconds": idle_timeout_seconds,
        "require_protected": require_protected,
        "deduplicate_retries": deduplicate_retries,
        "captures": [],
    }

    for entry in entries:
        if not entry.pcap.exists() and parser is None:
            raise FileNotFoundError(f"manifest capture does not exist: {entry.pcap}")
        scoped, scope_counts = parse(entry.pcap, entry.bssid)
        if entry.client_mac:
            scoped = [frame for frame in scoped if frame.client_mac == entry.client_mac]
        before_protection = len(scoped)
        if require_protected:
            scoped = [frame for frame in scoped if frame.observation.protected]
        sessions, session_stats = sessionize(
            scoped,
            capture_id=entry.source_session_id,
            idle_timeout_seconds=idle_timeout_seconds,
            deduplicate_retries=deduplicate_retries,
        )
        capture_windows = 0
        for window_index, window in enumerate(
            window_sessions(sessions, window_size=window_size, stride=stride, min_frames=min_frames)
        ):
            matrix = feature_matrix(window, window_size=window_size)
            record: dict[str, object] = {
                "sample_id": f"{entry.source_session_id}:{window.client_mac}:{window_index:05d}",
                "label": entry.label,
                # This is the group split key. It remains the manifest session
                # even if an idle gap yielded multiple derived client tracks.
                "source_session_id": entry.source_session_id,
                "track_id": window.session_id,
                "pcap": str(entry.pcap),
                "bssid": window.bssid,
                "client_mac": window.client_mac,
                "start_timestamp": window.start_timestamp,
                "end_timestamp": window.end_timestamp,
                "valid_frames": window.valid_frames,
                "schema_version": FEATURE_SCHEMA_VERSION,
                **entry.metadata,
            }
            for name, values in zip(FEATURE_COLUMNS, matrix):
                record[f"feature__{name}"] = values
            records.append(record)
            capture_windows += 1
        report["captures"].append({
            "pcap": str(entry.pcap),
            "label": entry.label,
            "bssid": entry.bssid,
            "source_session_id": entry.source_session_id,
            "client_mac": entry.client_mac,
            "scope_counts": scope_counts,
            "bssid_scoped_frames": before_protection,
            "frames_after_protection_filter": len(scoped),
            "session_stats": session_stats,
            "windows": capture_windows,
        })

    if not records:
        raise ManifestError(
            "dataset produced zero windows; verify BSSID/channel, protected-frame policy, "
            "client MAC, and min_frames"
        )
    df = pd.DataFrame.from_records(records)
    df.to_parquet(out, index=False)

    label_counts = df["label"].value_counts().sort_index().to_dict()
    group_counts = df["source_session_id"].nunique()
    report.update({
        "output": str(out),
        "samples": int(len(df)),
        "labels": {str(k): int(v) for k, v in label_counts.items()},
        "source_sessions": int(group_counts),
        "clients": int(df["client_mac"].nunique()),
    })
    report_path = out.with_suffix(out.suffix + ".report.json")
    metadata_path = out.with_suffix(out.suffix + ".meta.json")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    metadata_path.write_text(json.dumps({
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_columns": list(FEATURE_COLUMNS),
        "window_size": window_size,
        "label_values": sorted(str(v) for v in df["label"].unique()),
        "group_column": "source_session_id",
        "preprocessing": {
            "stride": stride,
            "min_frames": min_frames,
            "idle_timeout_seconds": idle_timeout_seconds,
            "require_protected": require_protected,
            "deduplicate_retries": deduplicate_retries,
        },
        "report": str(report_path),
    }, indent=2, sort_keys=True), encoding="utf-8")
    return report
