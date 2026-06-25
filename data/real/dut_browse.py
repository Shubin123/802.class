#!/usr/bin/env python3
"""
dut_browse.py — runs ON THE DUT (not the Mac). Loads a URL in a headless browser
for N seconds to generate realistic per-service traffic, which the Mac captures.

The `playwright` driver invokes this on the DUT (via the agent or nc transport).
Browser egress follows the DUT's routing table, so make Wi-Fi the DUT's default route
(the --iface arg is informational; browsers can't bind to an interface the way curl can).

Setup on the DUT:
    pip install playwright && playwright install chromium
"""
import argparse
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--iface", default="")  # informational only
    args = ap.parse_args()

    from playwright.sync_api import sync_playwright

    end = time.time() + args.seconds
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        while time.time() < end:
            try:
                page.goto(args.url, wait_until="networkidle", timeout=20000)
                for _ in range(3):           # scroll to pull lazy sub-resources
                    page.mouse.wheel(0, 2000)
                    time.sleep(1)
            except Exception:
                time.sleep(1)
        browser.close()


if __name__ == "__main__":
    main()
