from __future__ import annotations

import pytest

from wifi_app.contract import (
    Dot11Observation,
    feature_matrix,
    scope_to_bssid,
    scoped_feature_rows,
    sessionize,
    window_sessions,
)

from .helpers import BSSID, CLIENT_A, CLIENT_B, OTHER_BSSID, observation, scoped_frames


def test_bssid_ds_mapping_admits_both_directions_and_qos_data() -> None:
    uplink = scope_to_bssid(observation(direction="uplink", subtype=8), BSSID)
    downlink = scope_to_bssid(observation(direction="downlink", subtype=8), BSSID)
    assert uplink.accepted and uplink.frame is not None
    assert downlink.accepted and downlink.frame is not None
    assert uplink.frame.client_mac == CLIENT_A
    assert uplink.frame.direction == "uplink"
    assert downlink.frame.client_mac == CLIENT_A
    assert downlink.frame.direction == "downlink"


@pytest.mark.parametrize(
    ("frame", "reason"),
    [
        (observation(bssid=OTHER_BSSID), "different_bssid"),
        (Dot11Observation(0, 2, 0, False, False, CLIENT_A, "02:00:00:00:00:aa", BSSID), "non_infrastructure_data"),
        (Dot11Observation(0, 2, 0, True, True, BSSID, CLIENT_A, "02:00:00:00:00:aa", "02:00:00:00:00:bb"), "wds_or_four_address"),
        (observation(client="ff:ff:ff:ff:ff:ff"), "group_or_invalid_client"),
        (observation(subtype=12), "non_payload_data_subtype"),
    ],
)
def test_bssid_scoper_rejects_ambiguous_or_non_payload_frames(frame: Dot11Observation, reason: str) -> None:
    assert scope_to_bssid(frame, BSSID).reason == reason


def test_sessioning_is_per_client_and_retry_dedupe_is_scoped() -> None:
    frames = scoped_frames(count=2, client=CLIENT_A)
    # A retransmission with identical direction/TID/sequence is collapsed.
    retry = scope_to_bssid(observation(timestamp=0.1, client=CLIENT_A, retry=True, sequence_number=1), BSSID).frame
    # Same sequence from a distinct client remains valid.
    other_client = scope_to_bssid(observation(timestamp=0.1, client=CLIENT_B, sequence_number=1), BSSID).frame
    assert retry and other_client
    sessions, stats = sessionize([frames[0], retry, other_client, frames[1]], capture_id="cap", retry_dedupe_seconds=1.0)
    assert stats["dropped_retries"] == 1
    assert {session.client_mac for session in sessions} == {CLIENT_A, CLIENT_B}
    assert [len(session.frames) for session in sessions if session.client_mac == CLIENT_A] == [2]


def test_windowing_never_crosses_session_and_feature_padding_is_neutral() -> None:
    first = scoped_frames(count=5, client=CLIENT_A, start=0.0)
    second = scoped_frames(count=5, client=CLIENT_A, start=20.0)
    sessions, _ = sessionize(first + second, capture_id="cap", idle_timeout_seconds=5.0)
    windows = list(window_sessions(sessions, window_size=4, stride=2, min_frames=2))
    assert len(sessions) == 2
    assert all({frame.client_mac for frame in window.frames} == {CLIENT_A} for window in windows)
    assert all(window.frames[0].timestamp < 10 or window.frames[0].timestamp > 10 for window in windows)
    partial = [window for window in windows if window.valid_frames == 3][0]
    matrix = feature_matrix(partial, window_size=4)
    assert all(row[-1] == 0.0 for row in matrix)
    rows = scoped_feature_rows(sessions[0])
    assert rows[0]["iat_ms"] == 0.0
    assert rows[1]["iat_ms"] == pytest.approx(50.0)
