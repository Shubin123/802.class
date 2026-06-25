#!/usr/bin/env bash
# capture_mac.sh — record ONE real monitor-mode session on a MacBook's built-in Wi-Fi.
#
# macOS 14.4+ neutered `airport` (sniff is gone). This uses Wireshark's dumpcap,
# which on the built-in card sets BOTH monitor mode (-I) and the channel (-k <freq>).
#
# READ THIS:
#  • Monitor mode DISASSOCIATES Wi-Fi (en0). Your Mac must reach the network another
#    way (Ethernet) or it goes offline for the capture window — including any SSH
#    session. This script REFUSES to run if en0 is still your default route, unless
#    you pass --force.
#  • The Mac is the SNIFFER ONLY. A SEPARATE Wi-Fi device (phone/laptop = the "DUT")
#    must generate the traffic. The Mac cannot both monitor and browse on one radio.
#  • You do NOT need the WPA key — we use frame metadata, not decrypted payload.
#
# Usage:
#   sudo ./capture_mac.sh [--force] <label> <session> <freq[,width,center]> [seconds] [iface]
# Examples:
#   sudo ./capture_mac.sh 117 s01 5785 60               # 5GHz ch157, 20MHz (matches c157.pcapng)
#   sudo ./capture_mac.sh 117 s01 5785,VHT80,5775 60    # 5GHz ch157, 80MHz wide (center 5775)
#   sudo ./capture_mac.sh 12  s01 2412 60               # 2.4GHz ch1
#
# NOTE on width: the <type> token (HT20/HT40+/HT40-/VHT80/VHT160) is Wireshark-version
# specific. If your AP runs 80/160MHz and you capture at 20MHz, you'll see mgmt/ctrl
# frames but MISS most high-rate DATA frames (the ones we classify). For wide channels
# the Wireshark GUI width selector is the most reliable. Always sanity-check (README §2c).
#
# Channel→freq:  2.4GHz: ch n = 2407 + 5*n (ch1=2412, ch6=2437, ch11=2462)
#                5GHz:   ch n = 5000 + 5*n (ch36=5180, ch149=5745, ch157=5785, ch161=5805)
set -euo pipefail

FORCE=0
if [ "${1:-}" = "--force" ]; then FORCE=1; shift; fi

LABEL="${1:?CSTNET class id, e.g. 117}"
SESSION="${2:?session id, e.g. s01}"
FREQ="${3:?channel as frequency MHz, e.g. 5785 (ch157) or 5785,80,5775 for VHT80}"
SECS="${4:-60}"
IFACE="${5:-en0}"

DUMPCAP="/Applications/Wireshark.app/Contents/MacOS/dumpcap"
[ -x "$DUMPCAP" ] || DUMPCAP="$(command -v dumpcap || true)"
[ -n "$DUMPCAP" ] && [ -x "$DUMPCAP" ] || { echo "dumpcap not found — install Wireshark."; exit 1; }
CAPINFOS="$(dirname "$DUMPCAP")/capinfos"

# Guard: don't strand the Mac offline.
DEF_IF="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
if [ "$DEF_IF" = "$IFACE" ] && [ "$FORCE" -ne 1 ]; then
  echo "REFUSING: default route is '$IFACE' (Wi-Fi). Monitor mode will drop you offline."
  echo "  Activate Ethernet first: its adapter must show 'status: active' AND become the"
  echo "  default route (check: route -n get default | grep interface). Then retry."
  echo "  Override at your own risk with: sudo ./capture_mac.sh --force ..."
  exit 1
fi

OUT_DIR="$(cd "$(dirname "$0")" && pwd)/sessions"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/${LABEL}__${SESSION}.pcapng"

echo "[capture] $IFACE monitor @ freq $FREQ  ->  $OUT  (${SECS}s)"
echo "[capture] START loading service '$LABEL' on the DUT (the separate Wi-Fi device) NOW."
"$DUMPCAP" -i "$IFACE" -I -k "$FREQ" -a "duration:$SECS" -w "$OUT"

# Make the root-owned capture file usable by the normal user.
chown "${SUDO_USER:-$(whoami)}" "$OUT" 2>/dev/null || true

if [ -x "$CAPINFOS" ]; then
  echo "[capture] $("$CAPINFOS" -c -e "$OUT" 2>/dev/null | tr '\n' ' ')"
fi
echo "[capture] add to manifest.csv:"
echo "          sessions/${LABEL}__${SESSION}.pcapng,<DUT_WIFI_MAC>,${LABEL},${SESSION}"
