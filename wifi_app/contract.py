"""Canonical 802.11 field-pipeline contract.

This module is intentionally dependency-free so address scoping, retry policy,
sessioning, and feature generation can be tested without a capture adapter.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Literal, Optional, Sequence
import math
import re


FEATURE_SCHEMA_VERSION = "80211-metadata-v1"

# These are metadata only.  Ciphertext/body bytes are deliberately not part of
# the initial product schema; they may be evaluated later in a separate,
# explicitly-labelled ablation.
FEATURE_COLUMNS: tuple[str, ...] = (
    "direction",             # +1 uplink, -1 downlink
    "mpdu_len",
    "payload_len",
    "iat_ms",
    "log_iat",
    "is_retry",
    "seq_delta",
    "qos_tid",
    "has_qos",
    "is_protected",
    "subtype",
    "duration",
    "signal_dbm",
    "signal_missing",
    "data_rate",
    "rate_missing",
    "mcs_index",
    "mcs_missing",
)

# Data-bearing 802.11 data subtypes.  Null and QoS-Null frames (4/12) are
# intentionally excluded: they do not carry useful application traffic.
DATA_BEARING_SUBTYPES = frozenset({0, 1, 2, 3, 8, 9, 10, 11})

_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


def normalize_mac(value: str | None) -> str | None:
    """Return a normalized colon-separated MAC, or ``None`` for an empty value."""
    if value is None:
        return None
    result = str(value).strip().lower().replace("-", ":")
    if not result:
        return None
    if not _MAC_RE.fullmatch(result):
        raise ValueError(f"invalid MAC address: {value!r}")
    return result


def is_unicast_mac(value: str | None) -> bool:
    """Whether a normalized/normalizable MAC is an individually addressed MAC."""
    mac = normalize_mac(value)
    return bool(mac) and (int(mac.split(":", 1)[0], 16) & 1) == 0


@dataclass(frozen=True)
class Dot11Observation:
    """Capture-adapter-neutral view of one 802.11 frame.

    ``mpdu_len`` excludes radiotap.  ``payload_len`` is the observable bytes
    after the parsed Dot11 header; neither value promises FCS presence, which is
    capture-hardware dependent and recorded in capture metadata instead.
    """

    timestamp: float
    frame_type: int
    subtype: int
    to_ds: bool
    from_ds: bool
    addr1: str | None
    addr2: str | None
    addr3: str | None
    addr4: str | None = None
    mpdu_len: int = 0
    payload_len: int = 0
    protected: bool = False
    retry: bool = False
    sequence_number: int | None = None
    fragment_number: int | None = None
    qos_tid: int | None = None
    duration: int = 0
    signal_dbm: float | None = None
    data_rate: float | None = None
    mcs_index: int | None = None
    capture_index: int = 0

    def normalized(self) -> "Dot11Observation":
        """Normalize MAC fields and sanitize values supplied by adapters."""
        return Dot11Observation(
            timestamp=float(self.timestamp),
            frame_type=int(self.frame_type),
            subtype=int(self.subtype),
            to_ds=bool(self.to_ds),
            from_ds=bool(self.from_ds),
            addr1=normalize_mac(self.addr1),
            addr2=normalize_mac(self.addr2),
            addr3=normalize_mac(self.addr3),
            addr4=normalize_mac(self.addr4),
            mpdu_len=max(0, int(self.mpdu_len)),
            payload_len=max(0, int(self.payload_len)),
            protected=bool(self.protected),
            retry=bool(self.retry),
            sequence_number=(None if self.sequence_number is None else int(self.sequence_number) % 4096),
            fragment_number=(None if self.fragment_number is None else int(self.fragment_number) % 16),
            qos_tid=(None if self.qos_tid is None else max(0, min(15, int(self.qos_tid)))),
            duration=max(0, int(self.duration)),
            signal_dbm=(None if self.signal_dbm is None else float(self.signal_dbm)),
            data_rate=(None if self.data_rate is None else float(self.data_rate)),
            mcs_index=(None if self.mcs_index is None else int(self.mcs_index)),
            capture_index=max(0, int(self.capture_index)),
        )


Direction = Literal["uplink", "downlink"]


@dataclass(frozen=True)
class ScopedFrame:
    """A data-bearing infrastructure frame correctly scoped to one BSSID/client."""

    observation: Dot11Observation
    bssid: str
    client_mac: str
    direction: Direction

    @property
    def timestamp(self) -> float:
        return self.observation.timestamp


@dataclass(frozen=True)
class ScopeDecision:
    accepted: bool
    reason: str
    frame: ScopedFrame | None = None


def scope_to_bssid(observation: Dot11Observation, bssid: str) -> ScopeDecision:
    """Scope one observation to an infrastructure BSSID.

    Address mapping is intentionally narrow for v1:

    * ToDS=1, FromDS=0: ``addr1`` is the BSSID; ``addr2`` is the client.
    * ToDS=0, FromDS=1: ``addr2`` is the BSSID; ``addr1`` is the client.
    * 00 (IBSS/direct) and 11 (WDS/four-address) are rejected.

    The function returns a reason for every rejection, enabling capture-quality
    reporting rather than silently losing traffic.
    """
    frame = observation.normalized()
    target = normalize_mac(bssid)
    if target is None:
        raise ValueError("a BSSID is required")
    if frame.frame_type != 2:
        return ScopeDecision(False, "not_data")
    if frame.subtype not in DATA_BEARING_SUBTYPES:
        return ScopeDecision(False, "non_payload_data_subtype")
    if frame.to_ds and frame.from_ds:
        return ScopeDecision(False, "wds_or_four_address")
    if not frame.to_ds and not frame.from_ds:
        return ScopeDecision(False, "non_infrastructure_data")

    if frame.to_ds:
        if frame.addr1 != target:
            return ScopeDecision(False, "different_bssid")
        client = frame.addr2
        direction: Direction = "uplink"
    else:
        if frame.addr2 != target:
            return ScopeDecision(False, "different_bssid")
        client = frame.addr1
        direction = "downlink"

    if not is_unicast_mac(client):
        return ScopeDecision(False, "group_or_invalid_client")
    if client == target:
        return ScopeDecision(False, "invalid_client_equals_bssid")
    return ScopeDecision(True, "accepted", ScopedFrame(frame, target, client, direction))


@dataclass
class ClientSession:
    """Chronological BSSID-scoped trace for one client separated by idle gaps."""

    session_id: str
    bssid: str
    client_mac: str
    frames: list[ScopedFrame] = field(default_factory=list)

    @property
    def start_timestamp(self) -> float:
        return self.frames[0].timestamp if self.frames else 0.0

    @property
    def end_timestamp(self) -> float:
        return self.frames[-1].timestamp if self.frames else 0.0


@dataclass(frozen=True)
class Window:
    """Fixed-size model input source with an explicit count of real frames."""

    session_id: str
    bssid: str
    client_mac: str
    start_timestamp: float
    end_timestamp: float
    frames: tuple[ScopedFrame, ...]
    valid_frames: int


def sessionize(
    frames: Iterable[ScopedFrame],
    *,
    capture_id: str,
    idle_timeout_seconds: float = 15.0,
    deduplicate_retries: bool = True,
    retry_dedupe_seconds: float = 1.0,
) -> tuple[list[ClientSession], dict[str, int]]:
    """Create client sessions while retaining an auditable retry policy.

    A retry is collapsed only when a matching logical frame for the same client,
    direction, TID, sequence/fragment was seen recently.  A lone retry remains:
    a monitor can legitimately miss the original transmission.
    """
    if idle_timeout_seconds <= 0:
        raise ValueError("idle_timeout_seconds must be positive")
    if retry_dedupe_seconds < 0:
        raise ValueError("retry_dedupe_seconds cannot be negative")

    ordered = sorted(frames, key=lambda f: (f.timestamp, f.observation.capture_index))
    sessions: list[ClientSession] = []
    active: dict[str, ClientSession] = {}
    ordinal: defaultdict[str, int] = defaultdict(int)
    seen_logical: dict[tuple[str, str, int | None, int | None, int | None], float] = {}
    stats: defaultdict[str, int] = defaultdict(int)

    for scoped in ordered:
        stats["input_frames"] += 1
        obs = scoped.observation
        retry_key = (
            scoped.client_mac,
            scoped.direction,
            obs.qos_tid,
            obs.sequence_number,
            obs.fragment_number,
        )
        prior = seen_logical.get(retry_key)
        if (
            deduplicate_retries
            and obs.retry
            and prior is not None
            and 0.0 <= scoped.timestamp - prior <= retry_dedupe_seconds
        ):
            stats["dropped_retries"] += 1
            continue
        seen_logical[retry_key] = scoped.timestamp

        existing = active.get(scoped.client_mac)
        if existing is None or scoped.timestamp - existing.end_timestamp > idle_timeout_seconds:
            ordinal[scoped.client_mac] += 1
            session_id = f"{capture_id}:{scoped.client_mac}:{ordinal[scoped.client_mac]:03d}"
            existing = ClientSession(session_id, scoped.bssid, scoped.client_mac)
            active[scoped.client_mac] = existing
            sessions.append(existing)
            stats["sessions"] += 1
        existing.frames.append(scoped)
        stats["accepted_frames"] += 1

    return sessions, dict(stats)


def window_sessions(
    sessions: Iterable[ClientSession],
    *,
    window_size: int = 64,
    stride: int = 32,
    min_frames: int = 16,
) -> Iterator[Window]:
    """Yield fixed-width overlapping windows without crossing session boundaries."""
    if window_size <= 0 or stride <= 0:
        raise ValueError("window_size and stride must be positive")
    if not 1 <= min_frames <= window_size:
        raise ValueError("min_frames must be in 1..window_size")
    for session in sessions:
        n = len(session.frames)
        for start in range(0, n, stride):
            chunk = tuple(session.frames[start : start + window_size])
            if len(chunk) < min_frames:
                break
            yield Window(
                session_id=session.session_id,
                bssid=session.bssid,
                client_mac=session.client_mac,
                start_timestamp=chunk[0].timestamp,
                end_timestamp=chunk[-1].timestamp,
                frames=chunk,
                valid_frames=len(chunk),
            )


def scoped_feature_rows(session: ClientSession) -> list[dict[str, float]]:
    """Convert one session into the stable metadata schema.

    IAT and sequence state are scoped to this client session.  Missing radiotap
    values are represented by a neutral numeric value *and* an explicit mask;
    no radio feature is invented.
    """
    rows: list[dict[str, float]] = []
    last_timestamp: float | None = None
    last_seq: dict[Direction, int] = {}
    for scoped in session.frames:
        obs = scoped.observation
        iat_seconds = 0.0 if last_timestamp is None else max(0.0, scoped.timestamp - last_timestamp)
        # Prevent a long idle gap from dominating numeric ranges while retaining
        # the fact of a large gap.  The session splitter handles the larger cut.
        iat_ms = min(iat_seconds * 1000.0, 60_000.0)
        last_timestamp = scoped.timestamp

        prev_seq = last_seq.get(scoped.direction)
        seq_delta = 0 if prev_seq is None or obs.sequence_number is None else (obs.sequence_number - prev_seq) % 4096
        if obs.sequence_number is not None:
            last_seq[scoped.direction] = obs.sequence_number

        has_qos = obs.qos_tid is not None
        rows.append({
            "direction": 1.0 if scoped.direction == "uplink" else -1.0,
            "mpdu_len": float(obs.mpdu_len),
            "payload_len": float(obs.payload_len),
            "iat_ms": float(iat_ms),
            "log_iat": float(math.log1p(iat_ms)),
            "is_retry": float(obs.retry),
            "seq_delta": float(seq_delta),
            "qos_tid": float(obs.qos_tid if has_qos else 0),
            "has_qos": float(has_qos),
            "is_protected": float(obs.protected),
            "subtype": float(obs.subtype),
            "duration": float(obs.duration),
            "signal_dbm": float(obs.signal_dbm if obs.signal_dbm is not None else 0.0),
            "signal_missing": float(obs.signal_dbm is None),
            "data_rate": float(obs.data_rate if obs.data_rate is not None else 0.0),
            "rate_missing": float(obs.data_rate is None),
            "mcs_index": float(obs.mcs_index if obs.mcs_index is not None else 0.0),
            "mcs_missing": float(obs.mcs_index is None),
        })
    return rows


def feature_matrix(window: Window, *, window_size: int) -> list[list[float]]:
    """Return a zero-padded [features, window_size] matrix for one window."""
    session = ClientSession(window.session_id, window.bssid, window.client_mac, list(window.frames))
    rows = scoped_feature_rows(session)
    if window_size < len(rows):
        raise ValueError("window_size is smaller than the supplied window")
    return [
        [float(row[name]) for row in rows] + [0.0] * (window_size - len(rows))
        for name in FEATURE_COLUMNS
    ]
