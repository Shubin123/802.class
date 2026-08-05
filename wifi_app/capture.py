"""Adapters between monitor-mode PCAP/PCAPNG captures and the canonical contract."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .contract import Dot11Observation, ScopedFrame, normalize_mac, scope_to_bssid


class CaptureDependencyError(RuntimeError):
    """Raised when PCAP support is requested without Scapy installed."""


def _scapy():
    try:
        from scapy.all import Dot11, Dot11Elt, Dot11QoS, PcapReader, RadioTap, conf
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CaptureDependencyError(
            "PCAP/PCAPNG input requires scapy. Install project requirements first "
            "(python -m pip install -r requirements.txt)."
        ) from exc
    conf.verb = 0
    return Dot11, Dot11Elt, Dot11QoS, PcapReader, RadioTap


def _numeric_attr(obj: object, name: str, cast):
    try:
        value = getattr(obj, name)
        return None if value is None else cast(value)
    except (AttributeError, TypeError, ValueError):
        return None


def _dot11_observation(packet: object, capture_index: int) -> Dot11Observation | None:
    Dot11, _, Dot11QoS, _, RadioTap = _scapy()
    if not packet.haslayer(Dot11):
        return None
    dot11 = packet[Dot11]
    fc = int(dot11.FCfield or 0)
    sc = int(dot11.SC or 0)
    qos_tid = None
    if packet.haslayer(Dot11QoS):
        qos_tid = _numeric_attr(packet[Dot11QoS], "TID", int)

    rt = packet[RadioTap] if packet.haslayer(RadioTap) else None
    mpdu = bytes(dot11)
    payload = bytes(dot11.payload) if dot11.payload else b""
    return Dot11Observation(
        timestamp=float(packet.time),
        frame_type=int(dot11.type),
        subtype=int(dot11.subtype),
        to_ds=bool(fc & 0x01),
        from_ds=bool(fc & 0x02),
        addr1=getattr(dot11, "addr1", None),
        addr2=getattr(dot11, "addr2", None),
        addr3=getattr(dot11, "addr3", None),
        addr4=getattr(dot11, "addr4", None),
        mpdu_len=len(mpdu),
        payload_len=len(payload),
        protected=bool(fc & 0x40),
        retry=bool(fc & 0x08),
        sequence_number=(sc >> 4) & 0x0FFF,
        fragment_number=sc & 0x000F,
        qos_tid=qos_tid,
        duration=int(dot11.ID or 0),
        signal_dbm=(_numeric_attr(rt, "dBm_AntSignal", float) if rt is not None else None),
        data_rate=(_numeric_attr(rt, "Rate", float) if rt is not None else None),
        mcs_index=(_numeric_attr(rt, "MCS_index", int) if rt is not None else None),
        capture_index=capture_index,
    )


def iter_pcap_observations(path: str | Path) -> Iterator[Dot11Observation]:
    """Yield normalized raw 802.11 observations from a PCAP or PCAPNG file.

    Scapy's ``PcapReader`` dispatches both standard formats.  Radiotap is
    optional; adapter output retains masks later in the feature schema.
    """
    _, _, _, PcapReader, _ = _scapy()
    capture_path = Path(path)
    if not capture_path.exists():
        raise FileNotFoundError(capture_path)
    reader = PcapReader(str(capture_path))
    try:
        for index, packet in enumerate(reader):
            try:
                result = _dot11_observation(packet, index)
            except Exception:
                # Individual malformed records are an expected reality in radio
                # capture. The caller counts accepted/scoped frames rather than
                # claiming a lossless decode.
                continue
            if result is not None:
                yield result.normalized()
    finally:
        reader.close()


def scope_observations(
    observations: Iterable[Dot11Observation],
    bssid: str,
    *,
    client_mac: str | None = None,
) -> tuple[list[ScopedFrame], dict[str, int]]:
    """Apply the one BSSID scope contract to observations and return counters."""
    target_client = normalize_mac(client_mac)
    scoped: list[ScopedFrame] = []
    counts: Counter[str] = Counter()
    for observation in observations:
        decision = scope_to_bssid(observation, bssid)
        counts[decision.reason] += 1
        if not decision.accepted or decision.frame is None:
            continue
        if target_client and decision.frame.client_mac != target_client:
            counts["different_client"] += 1
            continue
        scoped.append(decision.frame)
    return scoped, dict(counts)


def scope_pcap(
    path: str | Path,
    bssid: str,
    *,
    client_mac: str | None = None,
) -> tuple[list[ScopedFrame], dict[str, int]]:
    """Read and BSSID-scope a PCAP/PCAPNG file."""
    return scope_observations(iter_pcap_observations(path), bssid, client_mac=client_mac)


@dataclass(frozen=True)
class BssidDiscovery:
    bssid: str
    beacon_count: int
    ssid: str | None
    channels_mhz: tuple[int, ...]


def discover_bssids(path: str | Path) -> list[BssidDiscovery]:
    """Discover beacon-advertised BSSIDs, SSIDs, and observed radio channels.

    This is deliberately an inspection helper, not a classifier input.  It helps
    operators distinguish a router's base/Ethernet MAC from the actual radio
    BSSID and lock their monitor radio to the relevant channel.
    """
    Dot11, Dot11Elt, _, PcapReader, RadioTap = _scapy()
    found: dict[str, dict[str, object]] = defaultdict(lambda: {"count": 0, "ssid": None, "channels": set()})
    reader = PcapReader(str(path))
    try:
        for packet in reader:
            if not packet.haslayer(Dot11):
                continue
            dot11 = packet[Dot11]
            if int(dot11.type) != 0 or int(dot11.subtype) != 8:
                continue
            try:
                bssid = normalize_mac(dot11.addr3)
            except ValueError:
                continue
            if not bssid:
                continue
            info = found[bssid]
            info["count"] = int(info["count"]) + 1
            if packet.haslayer(Dot11Elt):
                try:
                    raw_ssid = bytes(packet[Dot11Elt].info)
                    info["ssid"] = raw_ssid.decode("utf-8", errors="replace")
                except Exception:
                    pass
            if packet.haslayer(RadioTap):
                freq = _numeric_attr(packet[RadioTap], "ChannelFrequency", int)
                if freq:
                    channels = info["channels"]
                    assert isinstance(channels, set)
                    channels.add(freq)
    finally:
        reader.close()
    return [
        BssidDiscovery(bssid, int(info["count"]), info["ssid"] if isinstance(info["ssid"], str) else None,
                       tuple(sorted(info["channels"])))
        for bssid, info in sorted(found.items())
    ]
