import os
import sys
import glob
import time
import socket
import struct
import signal
import shutil
import logging
import textwrap
import subprocess
import threading
import ipaddress
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional

import numpy as np
import pandas as pd
import pyshark
from scapy.all import rdpcap, IP, TCP, Raw

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR   = Path(__file__).parent.resolve()
OUTPUT_DIR   = SCRIPT_DIR / "dataset_output"
PCAP_DIR     = OUTPUT_DIR / "captures"
FEATURE_DIR  = OUTPUT_DIR / "features"
DATASET_FILE = OUTPUT_DIR / "dataset.parquet"

AP_IFACE     = "wlan0"
STA_IFACE    = "wlan1"
MON_IFACE    = "wlan2"

AP_SSID      = "dataset-ap"
AP_PASS      = "datasetpass1234"     # >= 8 chars, WPA requirement
AP_CHANNEL   = 6
STA_IP       = "192.168.77.2"
AP_IP        = "192.168.77.1"
SUBNET       = "192.168.77.0/24"

REPLAY_PORT  = 19999                 # throwaway port; listener on AP side
REPLAY_DELAY = 0.0005                # seconds between send() calls
CAPTURE_TAIL = 3.0                   # extra seconds of capture after replay ends

RSSI_MEAN    = -65.0                 # dBm, realistic indoor mean
RSSI_SHADOW  = 4.0                   # dB,  per-flow shadowing std dev
RSSI_FAST    = 1.5                   # dB,  per-frame fast fading std dev

HOSTAPD_CONF   = "/tmp/dataset_hostapd.conf"
WPASUP_CONF    = "/tmp/dataset_wpa_supplicant.conf"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Phase 1 — Environment validation
# ---------------------------------------------------------------------------

def check_root() -> None:
    if os.geteuid() != 0:
        log.error("Must be run as root (sudo python3 build_dataset.py)")
        sys.exit(1)

def check_dependencies() -> None:
    missing = []
    for binary in ("hostapd", "wpa_supplicant", "tcpdump", "iw", "ip", "dhcpd"):
        if not shutil.which(binary):
            missing.append(binary)
    if missing:
        log.error("Missing binaries: %s", ", ".join(missing))
        log.error("Install with: apt install hostapd wpasupplicant tcpdump iw isc-dhcp-server")
        sys.exit(1)

def load_hwsim(n_radios: int = 3) -> None:
    """Load mac80211_hwsim with the required number of virtual radios."""
    result = subprocess.run(["lsmod"], capture_output=True, text=True)
    if "mac80211_hwsim" in result.stdout:
        log.info("mac80211_hwsim already loaded")
        return
    log.info("Loading mac80211_hwsim with %d radios", n_radios)
    r = subprocess.run(
        ["modprobe", "mac80211_hwsim", f"radios={n_radios}"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        log.error("modprobe failed: %s", r.stderr.strip())
        log.error("Ensure your kernel has mac80211_hwsim compiled in or as a module.")
        sys.exit(1)
    time.sleep(1)   # let udev settle

def discover_wlan_interfaces() -> List[str]:
    """Return all wlan* interfaces visible to the kernel."""
    result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    ifaces = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            ifaces.append(line.split()[1])
    return ifaces

def validate_environment() -> None:
    check_root()
    check_dependencies()
    load_hwsim(n_radios=3)
    ifaces = discover_wlan_interfaces()
    log.info("Virtual interfaces found: %s", ifaces)
    for required in (AP_IFACE, STA_IFACE, MON_IFACE):
        if required not in ifaces:
            log.error("Interface %s not found — hwsim may need more radios", required)
            sys.exit(1)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    FEATURE_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Phase 2 — Bring up AP, station, and monitor interface
# ---------------------------------------------------------------------------

_procs: List[subprocess.Popen] = []   # tracked for teardown

def run_bg(cmd: List[str], name: str) -> subprocess.Popen:
    """Launch a background process and register it for cleanup."""
    log.info("Starting %s: %s", name, " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _procs.append(p)
    return p

def shell(cmd: str, check: bool = True) -> str:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{r.stderr.strip()}")
    return r.stdout.strip()

def write_hostapd_conf() -> None:
    conf = textwrap.dedent(f"""\
        interface={AP_IFACE}
        driver=nl80211
        ssid={AP_SSID}
        hw_mode=g
        channel={AP_CHANNEL}
        macaddr_acl=0
        auth_algs=1
        ignore_broadcast_ssid=0
        wpa=2
        wpa_passphrase={AP_PASS}
        wpa_key_mgmt=WPA-PSK
        wpa_pairwise=CCMP
        rsn_pairwise=CCMP
    """)
    Path(HOSTAPD_CONF).write_text(conf)

def write_wpa_supplicant_conf() -> None:
    conf = textwrap.dedent(f"""\
        ctrl_interface=/var/run/wpa_supplicant
        update_config=1
        network={{
            ssid="{AP_SSID}"
            psk="{AP_PASS}"
            key_mgmt=WPA-PSK
        }}
    """)
    Path(WPASUP_CONF).write_text(conf)

def setup_ap_network() -> None:
    """Assign static IP to AP interface and set up a minimal DHCP-free config."""
    shell(f"ip link set {AP_IFACE} up")
    shell(f"ip addr flush dev {AP_IFACE}")
    shell(f"ip addr add {AP_IP}/24 dev {AP_IFACE}")

def setup_monitor() -> None:
    shell(f"ip link set {MON_IFACE} down")
    shell(f"iw dev {MON_IFACE} set type monitor")
    shell(f"ip link set {MON_IFACE} up")
    shell(f"iw dev {MON_IFACE} set channel {AP_CHANNEL}")
    log.info("%s in monitor mode on channel %d", MON_IFACE, AP_CHANNEL)

def start_virtual_network() -> None:
    write_hostapd_conf()
    write_wpa_supplicant_conf()
    setup_ap_network()
    setup_monitor()

    run_bg(["hostapd", HOSTAPD_CONF], "hostapd")
    time.sleep(2)

    run_bg(
        ["wpa_supplicant", "-B", f"-Dnl80211", f"-i{STA_IFACE}", f"-c{WPASUP_CONF}"],
        "wpa_supplicant",
    )
    time.sleep(3)

    # Assign static IP to station (avoid needing a DHCP server)
    shell(f"ip addr flush dev {STA_IFACE}")
    shell(f"ip addr add {STA_IP}/24 dev {STA_IFACE}")
    shell(f"ip route add {SUBNET} dev {STA_IFACE}", check=False)
    log.info("Station %s assigned %s", STA_IFACE, STA_IP)

    # Verify association
    time.sleep(2)
    status = shell(f"iw dev {STA_IFACE} link", check=False)
    if "Connected" not in status:
        log.warning("Station may not be fully associated yet — proceeding anyway")
    else:
        log.info("Station associated with AP")

def teardown_virtual_network() -> None:
    for p in _procs:
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            p.kill()
    shell(f"ip addr flush dev {AP_IFACE}", check=False)
    shell(f"ip addr flush dev {STA_IFACE}", check=False)
    shell(f"ip link set {MON_IFACE} down", check=False)
    shell(f"iw dev {MON_IFACE} set type managed", check=False)
    log.info("Virtual network torn down")

# ---------------------------------------------------------------------------
# Phase 3 — Extract per-label TCP flows from CSTNET pcaps
# ---------------------------------------------------------------------------

@dataclass
class Flow:
    label: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payloads: List[bytes] = field(default_factory=list)

def extract_flows(pcap_path: Path, label: str) -> List[Flow]:
    """
    Read a CSTNET pcap and reconstruct ordered TCP payload segments per flow.
    Returns a list of Flow objects, one per unique 5-tuple.
    """
    log.info("Extracting flows from %s (label=%s)", pcap_path.name, label)
    packets = rdpcap(str(pcap_path))

    flows: Dict[tuple, Flow] = {}
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        ip  = pkt[IP]
        tcp = pkt[TCP]
        key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        if key not in flows:
            flows[key] = Flow(
                label=label,
                src_ip=ip.src, dst_ip=ip.dst,
                src_port=tcp.sport, dst_port=tcp.dport,
            )
        flows[key].payloads.append(bytes(pkt[Raw]))

    result = [f for f in flows.values() if f.payloads]
    log.info("  %d flows extracted", len(result))
    return result

def load_all_cstnet_flows() -> Dict[str, List[Flow]]:
    """Find all cstnet_*.pcap files in the script directory and extract flows."""
    pattern = str(SCRIPT_DIR / "cstnet_*.pcap")
    pcap_files = sorted(glob.glob(pattern))
    if not pcap_files:
        log.error("No cstnet_*.pcap files found in %s", SCRIPT_DIR)
        sys.exit(1)
    log.info("Found %d CSTNET pcap file(s): %s",
             len(pcap_files), [Path(p).name for p in pcap_files])

    all_flows: Dict[str, List[Flow]] = {}
    for pcap_path in pcap_files:
        label = Path(pcap_path).stem.replace("cstnet_", "")
        all_flows[label] = extract_flows(Path(pcap_path), label)
    return all_flows

# ---------------------------------------------------------------------------
# Phase 4 — TCP replay through wlan1 + capture on wlan2
# ---------------------------------------------------------------------------

def _echo_server(stop_event: threading.Event) -> None:
    """
    Minimal TCP echo server bound to AP_IP:REPLAY_PORT.
    Accepts connections and drains incoming data — exists only so the
    station's connect() and send() calls succeed end-to-end through mac80211.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((AP_IP, REPLAY_PORT))
    srv.listen(64)
    srv.settimeout(1.0)
    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            threading.Thread(target=_drain, args=(conn,), daemon=True).start()
        except socket.timeout:
            pass
    srv.close()

def _drain(conn: socket.socket) -> None:
    conn.settimeout(2.0)
    try:
        while True:
            if not conn.recv(65536):
                break
    except Exception:
        pass
    finally:
        conn.close()

def replay_flow(flow: Flow) -> None:
    """Send all payloads in a flow through a real TCP socket bound to STA_IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((STA_IP, 0))
        s.settimeout(5.0)
        s.connect((AP_IP, REPLAY_PORT))
        for payload in flow.payloads:
            s.sendall(payload)
            time.sleep(REPLAY_DELAY)
        s.close()
    except Exception as e:
        log.debug("Flow replay error (%s → %s): %s", flow.src_ip, flow.dst_ip, e)

def capture_label(label: str, flows: List[Flow]) -> Optional[Path]:
    """
    Replay all flows for one label while capturing on the monitor interface.
    Returns the path to the captured pcap.
    """
    out_pcap = PCAP_DIR / f"{label}.pcap"

    # Start echo server on AP side
    stop_event = threading.Event()
    server_thread = threading.Thread(
        target=_echo_server, args=(stop_event,), daemon=True
    )
    server_thread.start()
    time.sleep(0.5)

    # Start tcpdump on monitor interface
    tcpdump_cmd = [
        "tcpdump", "-i", MON_IFACE,
        "-w", str(out_pcap),
        "--snapshot-length=0",
        "-U",                       # unbuffered write
        "not type mgt subtype beacon",   # skip beacons to keep pcap lean
    ]
    tcpdump_proc = subprocess.Popen(
        tcpdump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(0.5)   # let tcpdump initialise

    log.info("Replaying %d flows for label '%s'", len(flows), label)
    for i, flow in enumerate(flows):
        replay_flow(flow)
        if (i + 1) % 50 == 0:
            log.info("  %d / %d flows replayed", i + 1, len(flows))

    time.sleep(CAPTURE_TAIL)   # capture trailing frames

    tcpdump_proc.send_signal(signal.SIGINT)
    tcpdump_proc.wait(timeout=10)
    stop_event.set()
    server_thread.join(timeout=5)

    log.info("Capture saved: %s  (%d bytes)", out_pcap.name, out_pcap.stat().st_size)
    return out_pcap

def replay_and_capture(all_flows: Dict[str, List[Flow]]) -> Dict[str, Path]:
    """Run capture for every label. Returns {label: pcap_path}."""
    captured = {}
    for label, flows in all_flows.items():
        if not flows:
            log.warning("No flows for label '%s', skipping", label)
            continue
        pcap_path = capture_label(label, flows)
        captured[label] = pcap_path
    return captured

# ---------------------------------------------------------------------------
# Phase 5 — Feature extraction from labeled pcaps
# ---------------------------------------------------------------------------

def extract_features_from_pcap(pcap_path: Path, label: str) -> pd.DataFrame:
    """
    Parse a monitor-mode pcap with pyshark and return a DataFrame of
    per-frame features. Only data frames are included (type=2).
    """
    log.info("Extracting features from %s", pcap_path.name)
    records = []

    cap = pyshark.FileCapture(
        str(pcap_path),
        display_filter="wlan.fc.type == 2",   # data frames only
        use_json=True,
        include_raw=False,
    )

    prev_ts = None
    for pkt in cap:
        try:
            ts = float(pkt.sniff_timestamp)
            iat = (ts - prev_ts) if prev_ts is not None else 0.0
            prev_ts = ts

            wlan = pkt.wlan
            rt   = getattr(pkt, "radiotap", None)

            records.append({
                "label"         : label,
                "timestamp"     : ts,
                "iat"           : float(iat),
                "frame_len"     : int(pkt.length),
                "fc_type"       : int(wlan.fc_type),
                "fc_subtype"    : int(wlan.fc_subtype),
                "fc_retry"      : int(getattr(wlan, "fc_retry", 0)),
                "fc_protected"  : int(getattr(wlan, "fc_protected", 0)),
                "seq_num"       : int(getattr(wlan, "seq", 0)),
                "qos_tid"       : int(getattr(wlan, "qos_tid", 0)),
                "duration"      : int(getattr(wlan, "duration", 0)),
                "signal_dbm"    : float(getattr(rt, "dbm_antsignal", -30)),
                "data_rate"     : float(getattr(rt, "datarate", 0)),
                "mcs_index"     : int(getattr(rt, "mcs_index", 0)),
                "channel"       : int(getattr(rt, "channel_freq", AP_CHANNEL)),
            })
        except Exception:
            continue

    cap.close()
    df = pd.DataFrame(records)
    log.info("  %d frames extracted", len(df))
    return df

def extract_all_features(captured: Dict[str, Path]) -> pd.DataFrame:
    frames = []
    for label, pcap_path in captured.items():
        df = extract_features_from_pcap(pcap_path, label)
        if not df.empty:
            frames.append(df)
    if not frames:
        log.error("No features extracted — check pyshark and pcap contents")
        sys.exit(1)
    return pd.concat(frames, ignore_index=True)

# ---------------------------------------------------------------------------
# Phase 6 — RSSI / MCS augmentation
# ---------------------------------------------------------------------------

def augment_rssi(df: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    """
    Replace the flat hwsim signal_dbm with a two-component model:
      - Shadowing: one offset per (label, seq_block) — correlated within a flow
      - Fast fading: per-frame i.i.d. Gaussian
    Clipped to [-90, -20] dBm.
    """
    rng = np.random.default_rng(seed)
    df = df.copy()

    # Approximate flow identity via label + sequential block of 200 frames
    df["_flow_block"] = (df.groupby("label").cumcount() // 200).astype(str)
    df["_flow_id"]    = df["label"] + "_" + df["_flow_block"]

    flow_ids     = df["_flow_id"].unique()
    shadow_map   = {fid: rng.normal(0, RSSI_SHADOW) for fid in flow_ids}
    shadow       = df["_flow_id"].map(shadow_map).to_numpy()
    fast_fading  = rng.normal(0, RSSI_FAST, size=len(df))

    df["signal_dbm"] = (RSSI_MEAN + shadow + fast_fading).clip(-90, -20).astype(np.float32)
    df.drop(columns=["_flow_block", "_flow_id"], inplace=True)
    return df

def augment_mcs(df: pd.DataFrame) -> pd.DataFrame:
    """
    Assign a realistic MCS index based on augmented RSSI using the
    802.11n sensitivity ladder (approximate values for 20 MHz HT).
    """
    df = df.copy()
    rssi = df["signal_dbm"].to_numpy()
    conditions = [
        rssi >= -55, rssi >= -62, rssi >= -68,
        rssi >= -74, rssi >= -77, rssi >= -82, rssi >= -87,
    ]
    choices = [7, 6, 5, 4, 3, 2, 1]
    df["mcs_index"] = np.select(conditions, choices, default=0).astype(np.int8)
    return df

def augment_features(df: pd.DataFrame) -> pd.DataFrame:
    log.info("Augmenting RSSI and MCS index")
    df = augment_rssi(df)
    df = augment_mcs(df)

    # Derived features useful for classifiers
    df["frame_len_kb"]  = (df["frame_len"] / 1024).astype(np.float32)
    df["log_iat"]       = np.log1p(df["iat"]).astype(np.float32)
    return df

# ---------------------------------------------------------------------------
# Phase 7 — Save dataset
# ---------------------------------------------------------------------------

def save_dataset(df: pd.DataFrame) -> None:
    df.to_parquet(DATASET_FILE, index=False, compression="snappy")
    log.info("Dataset saved: %s", DATASET_FILE)
    log.info("Shape: %s", df.shape)
    log.info("Labels:\n%s", df["label"].value_counts().to_string())

    # Also save a per-label feature CSV for quick inspection
    summary = df.groupby("label").agg(
        frames=("frame_len", "count"),
        mean_len=("frame_len", "mean"),
        mean_rssi=("signal_dbm", "mean"),
        mean_mcs=("mcs_index", "mean"),
    ).round(2)
    summary_path = OUTPUT_DIR / "summary.csv"
    summary.to_csv(summary_path)
    log.info("Summary CSV: %s", summary_path)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("=" * 60)
    log.info("802.11 WPA dataset builder — CSTNET-TLS 1.3 source")
    log.info("=" * 60)

    # Phase 1
    log.info("[1/7] Validating environment")
    validate_environment()

    # Phase 2
    log.info("[2/7] Starting virtual network (hostapd + wpa_supplicant)")
    start_virtual_network()

    try:
        # Phase 3
        log.info("[3/7] Extracting TCP flows from CSTNET pcaps")
        all_flows = load_all_cstnet_flows()

        # Phase 4
        log.info("[4/7] Replaying flows through wlan1 + capturing on wlan2")
        captured = replay_and_capture(all_flows)

        # Phase 5
        log.info("[5/7] Extracting 802.11 features from monitor captures")
        df = extract_all_features(captured)

        # Phase 6
        log.info("[6/7] Augmenting RSSI and MCS")
        df = augment_features(df)

        # Phase 7
        log.info("[7/7] Saving dataset")
        save_dataset(df)

    finally:
        log.info("Tearing down virtual network")
        teardown_virtual_network()

    log.info("Done.")


if __name__ == "__main__":
    main()