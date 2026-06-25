#!/usr/bin/env bash
# dut_listen.sh — runs ON THE DUT. The zero-Python, keyless alternative to dut_agent.py:
# a netcat listener that runs whatever traffic command the orchestrator pushes over a
# plain LAN socket (no SSH, no keys). Pair with `collect.py --transport nc`.
#
# Trade-off vs dut_agent.py: no clock sync and no reported timestamps — the orchestrator
# brackets each window in its own clock (fine for one-file-per-service labeling). Use
# dut_agent.py when you want millisecond-accurate, DUT-reported windows.
#
# SECURITY: this executes commands received on the port via `sh`. Use ONLY on a trusted
# lab LAN. Reach it over the DUT's ETHERNET IP so control stays out of the Wi-Fi capture.
# Run as ROOT on Linux so the curl the orchestrator sends can hard-bind the Wi-Fi device.
#
# Usage on the DUT:
#   ./dut_listen.sh 9999
#
# Most netcat builds (macOS BSD, Linux netcat-openbsd, nmap ncat) accept `nc -l <port>`.
# GNU-traditional netcat needs `-l -p <port>` instead: run as  NC_PFLAG=1 ./dut_listen.sh 9999
set -u
PORT="${1:-9999}"
NC_PFLAG="${NC_PFLAG:-0}"
echo "[dut_listen] netcat control on :$PORT  (Ctrl-C to stop)"
while true; do
  if [ "$NC_PFLAG" = "1" ]; then
    nc -l -p "$PORT" | sh
  else
    nc -l "$PORT" | sh
  fi
done
