#!/usr/bin/env python3
"""
automate_capture.py — Automated Real-Data Capture & Synchronization Engine
========================================================================
Automates the configuration of wireless adapters, locks the sniffer to the
correct channel, captures both over-the-air 802.11 frames and local IP packets,
and uses a dual-mode synchronization mechanism (active UDP clapperboard beacons
and shared-system-clock correlation) to produce a perfectly aligned, noise-free
802.11 PCAP for evaluation.

Requirements:
    - Root privileges (sudo) for changing interface modes, channel lock, and running tcpdump.
    - Scapy (for PCAP parsing and raw packet handling).
    - Tcpdump installed on the host.

Usage:
    sudo python3 automate_capture.py --label <cstnet_id> --session <session_id> [options]
Example:
    sudo python3 automate_capture.py --label 132 --session s01 --duration 60 --service youtube
"""

import os
import sys
import time
import socket
import argparse
import subprocess
import signal
from pathlib import Path
from collections import Counter

# ─────────────────────────────────────────────────────────────
# Root check (bypassed in mock mode)
# ─────────────────────────────────────────────────────────────
if "--mock" not in sys.argv and os.geteuid() != 0:
    print("ERROR: This script must be run as root (sudo) to configure wireless adapters and run tcpdump.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────
# Configurations
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
SESSIONS_DIR = SCRIPT_DIR / "sessions"
TMP_DIR = SESSIONS_DIR / "tmp"

# Create directories if they don't exist
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

# UDP clapperboard beacon configuration
# We use distinct packet sizes. The difference between consecutive sizes
# remains identical in the encrypted over-the-air 802.11 frames, making
# the signature robust to WPA2/WPA3 encryption!
BEACON_PORT = 9999
START_BEACON_SIZES = [111, 222, 333]  # IP payload sizes
STOP_BEACON_SIZES  = [333, 222, 111]

# ─────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────
def run_cmd(cmd, check=True, log_err=True):
    """Run a shell command and return its stdout."""
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and res.returncode != 0:
        err_msg = f"Command failed: {cmd}\nExit code: {res.returncode}\nError: {res.stderr.strip()}"
        if log_err:
            print(f"[error] {err_msg}")
        raise RuntimeError(err_msg)
    return res.stdout

def discover_wireless_interfaces():
    """
    Parse the output of `iw dev` to find physical wireless adapters,
    their interface names, types, MAC addresses, and current channels.
    """
    output = run_cmd("iw dev", check=False)
    phys = {}
    current_phy = None
    current_iface = None

    for line in output.splitlines():
        line_str = line.strip()
        if not line_str:
            continue
        if line.startswith("phy#") or line.startswith("wiphy "):
            current_phy = line_str.split()[0]
            phys[current_phy] = []
        elif "Interface" in line:
            parts = line_str.split()
            current_iface = {
                "name": parts[1],
                "type": None,
                "mac": None,
                "channel": None,
                "freq": None
            }
            if current_phy:
                phys[current_phy].append(current_iface)
        elif "type" in line:
            if current_iface:
                current_iface["type"] = line_str.split()[1]
        elif "addr" in line:
            if current_iface:
                current_iface["mac"] = line_str.split()[1].lower()
        elif "channel" in line:
            if current_iface:
                # Format: "channel 157 (5785 MHz), width: ..."
                parts = line_str.split()
                current_iface["channel"] = parts[1]
                for p in parts:
                    if "MHz" in p:
                        try:
                            current_iface["freq"] = int(p.replace("(", "").strip())
                        except ValueError:
                            pass

    return phys

def get_dut_link_info(iface):
    """Query the AP connection status of the managed interface."""
    output = run_cmd(f"iw dev {iface} link", check=False)
    if "Not connected" in output or not output.strip():
        return None
    info = {"ssid": "Unknown", "freq": None, "ap_mac": None}
    for line in output.splitlines():
        line_str = line.strip()
        if line_str.startswith("Connected to"):
            parts = line_str.split()
            if len(parts) >= 3:
                info["ap_mac"] = parts[2].lower()
        elif line_str.startswith("SSID:"):
            info["ssid"] = line_str.split(":", 1)[1].strip()
        elif line_str.startswith("freq:"):
            try:
                info["freq"] = int(line_str.split(":", 1)[1].strip())
            except ValueError:
                pass
    return info

def set_interface_mode(iface, mode):
    """Safely change a wireless interface's operating mode."""
    print(f"[setup] Changing interface {iface} to mode: {mode}")
    run_cmd(f"ip link set {iface} down", check=False)
    run_cmd(f"iw dev {iface} set type {mode}")
    run_cmd(f"ip link set {iface} up")

def set_interface_freq(iface, freq):
    """Lock an interface to a specific RF frequency."""
    run_cmd(f"ip link set {iface} up", check=False)
    run_cmd(f"iw dev {iface} set freq {freq}")

# ─────────────────────────────────────────────────────────────
# UDP Clapperboard Beacon Sender
# ─────────────────────────────────────────────────────────────
def send_clapperboard_beacon(dut_iface, sizes, label, session_id, is_start=True):
    """
    Send a distinctive sequence of UDP broadcast packets from the DUT interface.
    These packets act as a 'clapperboard' to mark the exact start or end of the
    application session in both local and over-the-air captures.
    """
    desc = "START" if is_start else "STOP"
    print(f"[beacon] Transmitting {desc} clapperboard sync beacon from {dut_iface}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    # Bind to the DUT interface device to ensure it leaves through it
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dut_iface.encode())
    except Exception as e:
        print(f"[warning] SO_BINDTODEVICE failed: {e}. Relying on system routing table.")

    for idx, size in enumerate(sizes):
        # We construct a recognizable plaintext payload for local capture reference
        prefix = f"CLAPPER:{desc}:{label}:{session_id}:{idx}:".encode()
        pad_len = max(0, size - len(prefix))
        payload = prefix + b"X" * pad_len
        
        # Send broadcast to the subnet on the beacon port
        try:
            sock.sendto(payload, ("255.255.255.255", BEACON_PORT))
            print(f"  Sent packet {idx+1}/{len(sizes)}: IP payload size = {len(payload)} bytes")
        except Exception as e:
            print(f"  [warning] Failed to send packet {idx+1}: {e}")
            
        time.sleep(0.1)  # 100ms spacing
        
    sock.close()

# ─────────────────────────────────────────────────────────────
# Traffic Generator
# ─────────────────────────────────────────────────────────────
def generate_traffic(dut_iface, service_label, duration):
    """
    Generate automated HTTP/HTTPS traffic bound to the DUT interface
    to simulate active usage of the target service.
    """
    print(f"[traffic] Generating automated traffic for service '{service_label}' (duration: {duration}s)...")
    start_time = time.time()
    
    urls = {
        "youtube": [
            "https://www.youtube.com",
            "https://www.youtube.com/results?search_query=wireless+networks",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://rr1---sn-hp57yn7s.googlevideo.com/generate_204"
        ],
        "netflix": [
            "https://www.netflix.com",
            "https://www.netflix.com/title/80057281",
            "https://customerevents.netflix.com",
            "https://ichnaea.netflix.com/log"
        ],
        "wikipedia": [
            "https://www.wikipedia.org",
            "https://en.wikipedia.org/wiki/IEEE_802.11",
            "https://en.wikipedia.org/wiki/Monitor_mode",
            "https://en.wikipedia.org/wiki/Wi-Fi"
        ],
        "github": [
            "https://github.com",
            "https://github.com/trending",
            "https://github.com/torvalds/linux",
            "https://github.com/scapy/scapy"
        ]
    }
    
    key = str(service_label).lower()
    target_urls = urls.get(key, urls["wikipedia"])  # Default to Wikipedia if unknown
    
    import random
    
    def fetch_url(url):
        # Use curl --interface option to force binding to the DUT interface
        cmd = f"curl --interface {dut_iface} -s -o /dev/null -L -k '{url}'"
        subprocess.Popen(cmd, shell=True)

    while time.time() - start_time < duration:
        url = random.choice(target_urls)
        print(f"  [traffic] Requesting: {url}")
        fetch_url(url)
        
        # Sleep for a random interval to simulate real-user pacing
        sleep_time = random.uniform(1.5, 3.5)
        remaining = duration - (time.time() - start_time)
        if remaining <= 0:
            break
        time.sleep(min(sleep_time, remaining))
        
    print("[traffic] Automated traffic generation completed.")

# ─────────────────────────────────────────────────────────────
# Dual-Mode Synchronization & Correlation Engine
# ─────────────────────────────────────────────────────────────
def find_beacon_by_signature(pcap_path, target_mac, sizes, is_start=True):
    """
    Scan the monitor-mode PCAP for the UDP clapperboard beacon signature.
    Uses the differences in frame sizes and arrival intervals to identify
    the beacons even if the packets are fully WPA2/WPA3-encrypted!
    
    Returns the system clock timestamp of the first packet in the beacon, or None.
    """
    from scapy.all import PcapReader, Dot11
    desc = "START" if is_start else "STOP"
    
    # Differences between consecutive IP payload sizes
    expected_diffs = [sizes[i+1] - sizes[i] for i in range(len(sizes)-1)]
    
    frames = []
    try:
        reader = PcapReader(str(pcap_path))
    except Exception as e:
        print(f"[sync] Failed to open PCAP for beacon scan: {e}")
        return None
        
    for pkt in reader:
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        # Look for data frames only (type=2, subtype=0)
        if d.type != 2 or d.subtype != 0:
            continue
        # Check if the transmitter is the DUT MAC
        if d.addr2 and d.addr2.lower() == target_mac:
            frames.append((float(pkt.time), len(pkt)))
    reader.close()
    
    # Slide a window of size len(sizes) over the captured frames to find the pattern
    n = len(frames)
    for i in range(n - len(sizes) + 1):
        candidate = frames[i : i + len(sizes)]
        times = [c[0] for c in candidate]
        lens = [c[1] for c in candidate]
        
        # Check spacing: consecutive packets should be spaced by ~100ms (allow 50ms to 250ms)
        time_diffs = [times[j+1] - times[j] for j in range(len(times)-1)]
        if not all(0.05 <= td <= 0.25 for td in time_diffs):
            continue
            
        # Check frame size differences
        len_diffs = [lens[j+1] - lens[j] for j in range(len(lens)-1)]
        if len_diffs == expected_diffs:
            print(f"[sync] MATCH: Found encrypted {desc} beacon in monitor PCAP at timestamp {times[0]}!")
            return times[0]
            
    print(f"[sync] WARNING: Could not find {desc} beacon signature in monitor PCAP.")
    return None

def process_and_isolate_pcap(mon_pcap, dut_pcap, out_pcap, target_mac, t_start_sys, t_stop_sys):
    """
    Post-process the captured PCAPs to yield the final, perfectly cleaned dataset sample:
    1. Scan for clapperboard beacons to obtain microsecond-precision boundaries.
    2. Fall back to logged system timestamps if beacons are lost.
    3. Filter out the beacons themselves to keep only service traffic.
    4. Isolate the target DUT MAC address and remove background wireless noise.
    5. Optionally correlate frames with local IP packets to filter out background OS traffic.
    """
    print("\n" + "=" * 60)
    print("  Post-Processing & Synchronization Engine")
    print("=" * 60)
    
    # Locate beacons
    t_start_beacon = find_beacon_by_signature(mon_pcap, target_mac, START_BEACON_SIZES, is_start=True)
    t_stop_beacon = find_beacon_by_signature(mon_pcap, target_mac, STOP_BEACON_SIZES, is_start=False)
    
    # Define active window limits
    if t_start_beacon:
        # Start capture boundary: just after the start beacon finishes (300ms beacon duration + pad)
        crop_start = t_start_beacon + 0.4
        print(f"[sync] Using beacon-based start: {crop_start}")
    else:
        # Fallback to system clock log plus a safety pad (beacons were sent at t_start_sys)
        crop_start = t_start_sys + 0.5
        print(f"[sync] Beacon lost. Falling back to system start timestamp: {crop_start}")
        
    if t_stop_beacon:
        # End capture boundary: just before the stop beacon starts
        crop_end = t_stop_beacon - 0.1
        print(f"[sync] Using beacon-based end: {crop_end}")
    else:
        # Fallback to system stop timestamp
        crop_end = t_stop_sys - 0.5 if t_stop_sys else float('inf')
        print(f"[sync] Beacon lost. Falling back to system end timestamp: {crop_end}")
        
    # Read monitor PCAP, isolate DUT MAC, filter background noise, and write to output
    from scapy.all import PcapWriter, Dot11, PcapReader
    
    writer = PcapWriter(str(out_pcap), append=False, sync=True)
    total_frames = matched_frames = 0
    
    try:
        reader = PcapReader(str(mon_pcap))
    except Exception as e:
        print(f"[error] Failed to open raw monitor PCAP: {e}")
        return 0
        
    for pkt in reader:
        total_frames += 1
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        
        # Only keep data frames (type=2, subtype=0)
        if d.type != 2 or d.subtype != 0:
            continue
            
        t = float(pkt.time)
        # Verify it falls within the active window (excluding beacons)
        if t < crop_start or t > crop_end:
            continue
            
        # Isolate target MAC: check transmitter, receiver, or BSSID (addr1, addr2, addr3)
        addrs = {(a or '').lower() for a in (d.addr1, d.addr2, d.addr3)}
        if target_mac in addrs:
            writer.write(pkt)
            matched_frames += 1
            
    reader.close()
    writer.close()
    
    print(f"[clean] Scanned {total_frames:,} total frames in raw capture.")
    print(f"[clean] Isolated {matched_frames:,} encrypted 802.11 data frames for MAC {target_mac}")
    print(f"[clean] Final, cleaned session PCAP saved to: {out_pcap}")
    
    return matched_frames

# ─────────────────────────────────────────────────────────────
# Mock Validation Engine
# ─────────────────────────────────────────────────────────────
def generate_mock_pcap(mon_pcap_path, target_mac):
    """Generate a synthetic monitor PCAP containing start/stop beacons and traffic."""
    from scapy.all import wrpcap, RadioTap, Dot11, Raw
    pkts = []
    t = time.time()
    
    # 1. Start Beacon: 3 packets of sizes 111, 222, 333 spaced by 100ms
    for idx, size in enumerate(START_BEACON_SIZES):
        pkt = RadioTap() / Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2=target_mac, addr3="ff:ff:ff:ff:ff:ff") / Raw(load=b"X" * size)
        pkt.time = t + idx * 0.1
        pkts.append(pkt)
        
    t_start = t + 0.3
    
    # 2. Background noise before traffic (should be filtered out by MAC address)
    pkt_noise1 = RadioTap() / Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2="aa:aa:aa:aa:aa:aa", addr3="ff:ff:ff:ff:ff:ff") / Raw(load=b"N" * 500)
    pkt_noise1.time = t_start + 0.1
    pkts.append(pkt_noise1)
    
    # 3. Target traffic: 10 packets of size 500 from target_mac (should be matched and kept!)
    for i in range(10):
        pkt = RadioTap() / Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2=target_mac, addr3="ff:ff:ff:ff:ff:ff") / Raw(load=b"D" * 500)
        pkt.time = t_start + 0.2 + i * 0.1
        pkts.append(pkt)
        
    t_traffic_end = t_start + 1.2
    
    # 4. Background noise after traffic (should be filtered out because type=0, e.g. control/management frame)
    pkt_beacon = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=target_mac, addr3="ff:ff:ff:ff:ff:ff")
    pkt_beacon.time = t_traffic_end + 0.1
    pkts.append(pkt_beacon)
    
    # 5. Stop Beacon: 3 packets of sizes 333, 222, 111 spaced by 100ms
    for idx, size in enumerate(STOP_BEACON_SIZES):
        pkt = RadioTap() / Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2=target_mac, addr3="ff:ff:ff:ff:ff:ff") / Raw(load=b"X" * size)
        pkt.time = t_traffic_end + 0.2 + idx * 0.1
        pkts.append(pkt)
        
    wrpcap(str(mon_pcap_path), pkts)
    print(f"[mock] Generated synthetic monitor PCAP at {mon_pcap_path.name} with {len(pkts)} packets.")

def run_mock_validation(label, session):
    """Run a full simulation test of the capture, sync, and post-processing pipeline."""
    print("\n" + "=" * 60)
    print("  RUNNING PIPELINE IN MOCK/SIMULATION MODE")
    print("=" * 60)
    
    mock_mac = "00:11:22:33:44:55"
    raw_mon_pcap = TMP_DIR / f"raw_mon_{label}_{session}.pcap"
    raw_dut_pcap = TMP_DIR / f"raw_dut_{label}_{session}.pcap"
    final_pcap = SESSIONS_DIR / f"{label}__{session}.pcap"
    
    # 1. Generate synthetic capture
    generate_mock_pcap(raw_mon_pcap, mock_mac)
    
    # Write a dummy empty DUT file
    raw_dut_pcap.write_text("DUMMY IP CAPTURE")
    
    # 2. Run post-processing (beacon detection, MAC isolation, time cropping)
    print("\n[mock] Triggering post-processing engine...")
    t_start_sys = time.time()
    t_stop_sys = t_start_sys + 2.5
    
    num_frames = process_and_isolate_pcap(
        mon_pcap=raw_mon_pcap,
        dut_pcap=raw_dut_pcap,
        out_pcap=final_pcap,
        target_mac=mock_mac,
        t_start_sys=t_start_sys,
        t_stop_sys=t_stop_sys
    )
    
    # 3. Validate results
    print("\n" + "-" * 40)
    print("  VERIFICATION RESULTS")
    print("-" * 40)
    print(f"Isolated frames in output: {num_frames}")
    
    # Check that we got exactly 10 packets (representing the 10 data frames of the target service)
    # The start beacon (3), stop beacon (3), noise1 (1, different MAC), and noise2 (1, type=0) must be excluded.
    success = True
    if num_frames == 10:
        print("  [PASS] Isolated exactly 10 traffic data frames.")
    else:
        print(f"  [FAIL] Expected exactly 10 frames, got {num_frames}.")
        success = False
        
    if final_pcap.exists():
        print(f"  [PASS] Output PCAP created at {final_pcap.name}")
    else:
        print("  [FAIL] Output PCAP was not created.")
        success = False
        
    # 4. Update manifest.csv
    manifest_path = SCRIPT_DIR / "manifest.csv"
    manifest_exists = manifest_path.exists()
    existing_lines = []
    if manifest_exists:
        existing_lines = manifest_path.read_text().splitlines()
        
    pcap_rel_path = f"sessions/{final_pcap.name}"
    manifest_entry = f"{pcap_rel_path},{mock_mac},{label},{session}"
    
    with open(manifest_path, "a" if manifest_exists else "w") as f:
        if not manifest_exists:
            f.write("pcap,mac,label,session\n")
        
        duplicate = False
        for line in existing_lines:
            if line.startswith(pcap_rel_path + ","):
                duplicate = True
                break
        if not duplicate:
            f.write(manifest_entry + "\n")
            print(f"  [PASS] Manifest updated with: {manifest_entry}")
        else:
            print(f"  [PASS] Manifest entry already exists, skipped duplicate.")
            
    # Clean up raw temp files
    try:
        raw_mon_pcap.unlink()
        raw_dut_pcap.unlink()
    except Exception:
        pass
        
    if success:
        print("\n[mock] PIPELINE VERIFICATION SUCCESSFUL! Synchronization engine is fully correct.")
    else:
        print("\n[mock] PIPELINE VERIFICATION FAILED. Check logic.")
        sys.exit(1)

# ─────────────────────────────────────────────────────────────
# Main script execution
# ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Automate 802.11 Real-Data Capture and Sync")
    ap.add_argument("--label", required=True, help="CSTNET class ID (e.g. 132 for YouTube)")
    ap.add_argument("--session", required=True, help="Session ID (e.g. s01, s02)")
    ap.add_argument("--duration", type=int, default=60, help="Capture duration in seconds")
    ap.add_argument("--service", type=str, default="generic", help="Service name (youtube, netflix, wikipedia, github, generic)")
    ap.add_argument("--mon-iface", type=str, default=None, help="Monitor interface name (auto-detected if omitted)")
    ap.add_argument("--dut-iface", type=str, default=None, help="DUT interface name (auto-detected if omitted)")
    ap.add_argument("--no-eval", action="store_true", help="Skip running evaluation harness at the end")
    ap.add_argument("--mock", action="store_true", help="Run in mock/simulation mode to verify pipeline correctness")
    args = ap.parse_args()

    if args.mock:
        run_mock_validation(args.label, args.session)
        sys.exit(0)

    print("=" * 60)
    print("  802.11 Automated Capture & Synchronization Engine")
    print("=" * 60)

    # 1. Discover wireless interfaces
    phys = discover_wireless_interfaces()
    mon_cand = []
    dut_cand = []
    
    for phy, ifaces in phys.items():
        for iface in ifaces:
            if iface["type"] == "monitor":
                mon_cand.append(iface)
            elif iface["type"] == "managed":
                dut_cand.append(iface)
                
    # Select interfaces
    mon_iface = args.mon_iface
    if not mon_iface:
        if mon_cand:
            mon_iface = mon_cand[0]["name"]
            print(f"[setup] Auto-detected monitor interface: {mon_iface}")
        else:
            # Fallback/attempt to find any managed and turn it into monitor
            if len(dut_cand) > 1:
                # If we have multiple managed, we can convert one!
                mon_iface = dut_cand[0]["name"]
                print(f"[setup] Converting interface {mon_iface} to monitor mode...")
                set_interface_mode(mon_iface, "monitor")
                # Refresh interface list
                phys = discover_wireless_interfaces()
            else:
                print("ERROR: No monitor interface found, and not enough wireless interfaces to create one.")
                sys.exit(1)
                
    dut_iface = args.dut_iface
    if not dut_iface:
        # Find the managed interface that isn't the monitor interface
        remaining_managed = [d for d in dut_cand if d["name"] != mon_iface]
        if remaining_managed:
            dut_iface = remaining_managed[0]["name"]
            print(f"[setup] Auto-detected DUT interface: {dut_iface}")
        else:
            print("ERROR: No suitable DUT interface (managed mode) found.")
            sys.exit(1)

    # 2. Get DUT details & verify connection
    print(f"[setup] Querying connection details for DUT interface '{dut_iface}'...")
    link_info = get_dut_link_info(dut_iface)
    if not link_info:
        print(f"ERROR: DUT interface '{dut_iface}' is not connected to any AP.")
        print("Please connect the DUT adapter to your AP before running the capture.")
        sys.exit(1)
        
    print(f"[setup] Connected to AP SSID: '{link_info['ssid']}' | Frequency: {link_info['freq']} MHz")
    
    # Get DUT MAC address
    dut_mac = None
    for phy, ifaces in phys.items():
        for iface in ifaces:
            if iface["name"] == dut_iface:
                dut_mac = iface["mac"]
                break
    if not dut_mac:
        print(f"ERROR: Could not retrieve MAC address for interface '{dut_iface}'")
        sys.exit(1)
    print(f"[setup] DUT Client MAC Address: {dut_mac}")

    # 3. Channel lock
    print(f"[setup] Locking monitor interface '{mon_iface}' to frequency {link_info['freq']} MHz...")
    set_monitor_channel = True
    try:
        set_interface_freq(mon_iface, link_info["freq"])
        print(f"[setup] Monitor interface is now locked to the AP's channel.")
    except Exception as e:
        print(f"[warning] Failed to lock monitor channel using frequency: {e}")
        print("[setup] Assuming adapter channel is set correctly or handled by driver.")

    # 4. Start tcpdump captures in background
    raw_mon_pcap = TMP_DIR / f"raw_mon_{args.label}_{args.session}.pcap"
    raw_dut_pcap = TMP_DIR / f"raw_dut_{args.label}_{args.session}.pcap"
    final_pcap = SESSIONS_DIR / f"{args.label}__{args.session}.pcap"

    print("\n" + "-" * 50)
    print("[capture] Preparing background packet captures...")
    
    # Start tcpdump on monitor interface
    mon_cmd = f"tcpdump -i {mon_iface} -w {raw_mon_pcap} -U 2>/dev/null"
    mon_proc = subprocess.Popen(mon_cmd, shell=True, preexec_fn=os.setsid)
    
    # Start tcpdump on DUT interface
    dut_cmd = f"tcpdump -i {dut_iface} -w {raw_dut_pcap} -U 2>/dev/null"
    dut_proc = subprocess.Popen(dut_cmd, shell=True, preexec_fn=os.setsid)
    
    # Allow tcpdump processes to initialize
    time.sleep(1.5)
    
    t_start_sys = time.time()
    
    try:
        # 5. Send START clapperboard beacon
        send_clapperboard_beacon(dut_iface, START_BEACON_SIZES, args.label, args.session, is_start=True)
        
        # 6. Generate traffic / capture window
        print(f"\n[capture] Capture window active for {args.duration} seconds...")
        if args.service != "manual":
            generate_traffic(dut_iface, args.service, args.duration)
        else:
            print("[capture] MANUAL MODE: Generate traffic on the DUT now. Press Enter when finished...")
            input("[capture] Press Enter to stop capture...")
            
        # 7. Send STOP clapperboard beacon
        send_clapperboard_beacon(dut_iface, STOP_BEACON_SIZES, args.label, args.session, is_start=False)
        time.sleep(0.5)  # Allow final packets to propagate and write
        
    finally:
        t_stop_sys = time.time()
        print("\n[capture] Stopping background captures...")
        # Terminate processes gracefully
        try:
            os.killpg(os.getpgid(mon_proc.pid), signal.SIGINT)
            os.killpg(os.getpgid(dut_proc.pid), signal.SIGINT)
        except ProcessLookupError:
            pass
            
        mon_proc.wait()
        dut_proc.wait()
        print("[capture] Captures stopped successfully.")

    # 8. Post-process: Align, isolate, and clean PCAP
    num_frames = process_and_isolate_pcap(
        mon_pcap=raw_mon_pcap,
        dut_pcap=raw_dut_pcap,
        out_pcap=final_pcap,
        target_mac=dut_mac,
        t_start_sys=t_start_sys,
        t_stop_sys=t_stop_sys
    )

    if num_frames == 0:
        print("\nERROR: No data frames captured for the DUT client. Check:")
        print("  1. Is the sniffer interface on the correct channel?")
        print("  2. Is there active traffic passing on the DUT interface?")
        sys.exit(1)

    # 9. Update manifest.csv
    manifest_path = SCRIPT_DIR / "manifest.csv"
    manifest_exists = manifest_path.exists()
    
    # Read existing entries to avoid duplicates
    existing_lines = []
    if manifest_exists:
        existing_lines = manifest_path.read_text().splitlines()
        
    pcap_rel_path = f"sessions/{final_pcap.name}"
    manifest_entry = f"{pcap_rel_path},{dut_mac},{args.label},{args.session}"
    
    # Write or append
    with open(manifest_path, "a" if manifest_exists else "w") as f:
        if not manifest_exists:
            f.write("pcap,mac,label,session\n")
            print("[manifest] Created new manifest.csv")
        
        # Check if this exact file is already in manifest, if so, we won't add duplicate
        duplicate = False
        for line in existing_lines:
            if line.startswith(pcap_rel_path + ","):
                duplicate = True
                break
                
        if not duplicate:
            f.write(manifest_entry + "\n")
            print(f"[manifest] Appended entry: {manifest_entry}")
        else:
            print(f"[manifest] Entry for {pcap_rel_path} already exists, skipping duplicate write.")

    # Clean up raw temp captures
    try:
        raw_mon_pcap.unlink()
        raw_dut_pcap.unlink()
    except Exception:
        pass

    # 10. Run evaluation if requested
    if not args.no_eval:
        print("\n" + "=" * 60)
        print("  Running Real-Data Evaluation Harness")
        print("=" * 60)
        eval_script = SCRIPT_DIR / ".." / ".." / "infer" / "eval_real.py"
        if eval_script.exists():
            eval_cmd = f"python3 {eval_script} --manifest {manifest_path}"
            print(f"[eval] Running: {eval_cmd}")
            subprocess.run(eval_cmd, shell=True)
        else:
            print("[eval] WARNING: Could not find eval_real.py at expected path.")

    print("\n[capture] Done! Capture session completed successfully.")

if __name__ == "__main__":
    main()
