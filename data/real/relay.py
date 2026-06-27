#!/usr/bin/env python3
"""
relay.py — run this ON THE MAC, in your normal (unrestricted) terminal.

The agent's sandbox can reach 127.0.0.1 but NOT the 10.0.0.x LAN. Your normal shell
CAN reach the DUT over the LAN. This relay bridges the two: it listens on loopback
and forwards each connection to the DUT, so the agent drives the DUT through it.

  127.0.0.1:12222  ->  <DUT>:2222   (DUT SSH — used once to start the agent)
  127.0.0.1:19999  ->  <DUT>:9999   (DUT traffic agent)

Each inbound connection opens a FRESH connection to the DUT (no persistent SSH
tunnel to flap, no single-session conflict). No sudo, no password to run this.

Usage:
    python3 relay.py                 # defaults to DUT 10.0.0.213
    python3 relay.py --dut 10.0.0.213
"""
import argparse
import socket
import threading


def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client, dut, dport):
    try:
        remote = socket.create_connection((dut, dport), timeout=10)
    except OSError as e:
        print(f"  [relay] DUT {dut}:{dport} unreachable right now: {e}", flush=True)
        client.close()
        return
    threading.Thread(target=pipe, args=(client, remote), daemon=True).start()
    threading.Thread(target=pipe, args=(remote, client), daemon=True).start()


def listener(lport, dut, dport):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", lport))
    s.listen(50)
    print(f"  127.0.0.1:{lport}  ->  {dut}:{dport}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c, dut, dport), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dut", default="10.0.0.213")
    ap.add_argument("--map", nargs="+", default=["12222:2222", "19999:9999"],
                    help="loopback_port:dut_port pairs")
    a = ap.parse_args()
    print(f"relay up (DUT={a.dut}) — leave this running, Ctrl-C to stop:")
    for m in a.map:
        lp, dp = m.split(":")
        threading.Thread(target=listener, args=(int(lp), a.dut, int(dp)), daemon=True).start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
