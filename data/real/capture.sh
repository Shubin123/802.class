#!/usr/bin/env bash
# capture.sh — record ONE real over-the-air monitor-mode session for ONE service.
#
# You drive the browser by hand (or with a script) while this captures. One
# service per timed window keeps labels clean. You do NOT need the WPA key —
# we only use frame metadata (sizes/timing/direction), not the payload.
#
# Usage:
#   sudo ./capture.sh <mon_iface> <channel> <label> <session> [seconds]
# Example:
#   sudo ./capture.sh wlan1mon 36 132 s01 60     # youtube (CSTNET id 132), session s01, 60s
#
# Steps it does NOT do for you:
#   1. Put the adapter in monitor mode on the AP's channel (see README.md).
#   2. Start loading the target service on the DUT before/at capture start.
set -euo pipefail

IFACE="${1:?monitor iface, e.g. wlan1mon}"
CHANNEL="${2:?AP channel, e.g. 36}"
LABEL="${3:?CSTNET class id, e.g. 132}"
SESSION="${4:?session id, e.g. s01}"
SECONDS_DUR="${5:-60}"

OUT_DIR="$(cd "$(dirname "$0")" && pwd)/sessions"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/${LABEL}__${SESSION}.pcap"

# Lock the monitor iface to the AP channel (data frames only land if you're on it).
iw dev "$IFACE" set channel "$CHANNEL" 2>/dev/null || true

echo "[capture] iface=$IFACE channel=$CHANNEL -> $OUT  (${SECONDS_DUR}s)"
echo "[capture] START loading service '$LABEL' on the DUT NOW."
# Capture data frames (type 2) only, full length. -G one-shot timeout, -W 1 file.
timeout "${SECONDS_DUR}s" tcpdump -i "$IFACE" -w "$OUT" --snapshot-length=0 -U \
    'wlan type data' || true

FRAMES=$(tcpdump -r "$OUT" 2>/dev/null | wc -l | tr -d ' ')
echo "[capture] saved $OUT  (~$FRAMES frames)"
echo "[capture] add this line to manifest.csv:"
echo "          sessions/${LABEL}__${SESSION}.pcap,<DUT_MAC>,${LABEL},${SESSION}"
