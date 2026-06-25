#!/usr/bin/env python3
"""
sync.py — shared control channel + clock sync between the orchestrator (on the
sniffer) and the DUT agent (on the traffic generator). Stdlib only; byte-identical
behavior on macOS and Linux.

Wire protocol
-------------
Length-prefixed JSON:  [4-byte big-endian length][utf-8 JSON].  One request →
one response, sequential, over a single persistent TCP connection.

Clock sync
----------
NTP-style 4-timestamp exchange (t0=orch send, t1=dut recv, t2=dut send, t3=orch
recv). We compute the offset such that:

    orchestrator_time ≈ dut_time - offset

so any DUT-side timestamp (when traffic actually started/stopped) can be expressed
in the sniffer's clock — which is exactly the clock the captured pcap frames use,
making the capture↔service mapping verifiable to the millisecond. Several samples
are taken and the one with the smallest round-trip delay wins (least queuing noise).
"""
import json
import socket
import struct
import time

PROTOCOL_VERSION = 1
DEFAULT_PORT = 9999


def send_msg(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_msg(sock):
    hdr = _recvn(sock, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack("!I", hdr)
    body = _recvn(sock, n)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


def estimate_offset(sock, samples=9):
    """Return (offset, delay).  orchestrator_time ≈ dut_time - offset; delay = best RTT(s)."""
    best = None
    for _ in range(samples):
        t0 = time.time()
        send_msg(sock, {"cmd": "ping", "t0": t0})
        r = recv_msg(sock)
        t3 = time.time()
        if not r or "t1" not in r:
            continue
        t1, t2 = r["t1"], r["t2"]
        delay = (t3 - t0) - (t2 - t1)            # round-trip minus server processing
        offset = ((t1 - t0) + (t2 - t3)) / 2.0   # amount DUT clock leads orch clock
        if best is None or delay < best[1]:
            best = (offset, delay)
        time.sleep(0.02)
    return best if best else (0.0, float("inf"))


class AgentClient:
    """Orchestrator side: drives a dut_agent.py over the control channel."""

    def __init__(self, host, port=DEFAULT_PORT, timeout=30):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = None
        self.offset = 0.0
        self.delay = float("inf")
        self.info = {}

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(None)
        send_msg(self.sock, {"cmd": "hello", "version": PROTOCOL_VERSION})
        r = recv_msg(self.sock)
        if not r or not r.get("ok"):
            raise RuntimeError(f"DUT hello failed: {r}")
        self.info = r
        return r

    def sync_clock(self, samples=9):
        self.offset, self.delay = estimate_offset(self.sock, samples)
        return self.offset, self.delay

    def dut_to_orch(self, dut_ts):
        """Convert a DUT timestamp into the orchestrator/sniffer (pcap) clock."""
        return dut_ts - self.offset

    def generate(self, url, seconds, driver="curl", iface=None, sid=None):
        send_msg(self.sock, {"cmd": "generate", "url": url, "seconds": seconds,
                             "driver": driver, "iface": iface, "id": sid})
        self.sock.settimeout(seconds + 60)       # generate blocks ~seconds on the DUT
        r = recv_msg(self.sock)
        self.sock.settimeout(None)
        if not r or not r.get("ok"):
            raise RuntimeError(f"generate failed: {r}")
        return r                                  # {start, end (DUT clock), requests, ...}

    def close(self):
        try:
            send_msg(self.sock, {"cmd": "bye"})
            recv_msg(self.sock)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
