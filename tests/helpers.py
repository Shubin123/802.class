from __future__ import annotations

from wifi_app.contract import Dot11Observation, ScopedFrame


BSSID = "02:00:00:00:00:01"
CLIENT_A = "02:00:00:00:00:11"
CLIENT_B = "02:00:00:00:00:22"
OTHER_BSSID = "02:00:00:00:00:02"


def observation(
    *,
    timestamp: float = 0.0,
    client: str = CLIENT_A,
    direction: str = "uplink",
    bssid: str = BSSID,
    subtype: int = 8,
    protected: bool = True,
    retry: bool = False,
    sequence_number: int = 1,
    qos_tid: int | None = 3,
    capture_index: int = 0,
) -> Dot11Observation:
    if direction == "uplink":
        return Dot11Observation(
            timestamp=timestamp, frame_type=2, subtype=subtype, to_ds=True, from_ds=False,
            addr1=bssid, addr2=client, addr3="02:00:00:00:00:aa", mpdu_len=120,
            payload_len=90, protected=protected, retry=retry, sequence_number=sequence_number,
            qos_tid=qos_tid, duration=30, capture_index=capture_index,
        )
    return Dot11Observation(
        timestamp=timestamp, frame_type=2, subtype=subtype, to_ds=False, from_ds=True,
        addr1=client, addr2=bssid, addr3="02:00:00:00:00:aa", mpdu_len=140,
        payload_len=110, protected=protected, retry=retry, sequence_number=sequence_number,
        qos_tid=qos_tid, duration=20, capture_index=capture_index,
    )


def scoped_frames(*, count: int = 8, client: str = CLIENT_A, start: float = 0.0, bssid: str = BSSID) -> list[ScopedFrame]:
    from wifi_app.contract import scope_to_bssid

    result = []
    for index in range(count):
        decision = scope_to_bssid(observation(
            timestamp=start + index * 0.05,
            client=client,
            bssid=bssid,
            direction="uplink" if index % 2 == 0 else "downlink",
            sequence_number=index + 1,
            capture_index=index,
        ), bssid)
        assert decision.frame is not None
        result.append(decision.frame)
    return result
