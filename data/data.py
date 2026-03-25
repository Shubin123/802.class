"""
build_dataset.py
================
Builds a WPA-encrypted 802.11 monitor-mode dataset from ET-BERT / CSTNET-TLS 1.3
.npy packet byte files.

.npy format
-------------------
Each file encodes one traffic class. Two layouts are handled automatically:

  Layout A — plain array  (from datasets/main.py splitcap=True)
      shape : (N, L)   dtype : uint8 or int16
      Each row is one packet's byte sequence (Ethernet/IP stripped, TCP ports
      zeroed), padded / truncated to L bytes.

  Layout B — dict / structured  (from data_process/data_preprocess.py)
      Keys include 'payload', 'len_train', 'time_train', etc.
      'payload' value has shape (N, L).

File discovery
--------------
The script looks for .npy files in three ways, in order:

  1. ET-BERT tree   datasets/cstnet-tls1.3/<label>/<split>.npy
  2. Flat layout    <label>.npy   (all .npy files next to this script)
  3. Combined       dataset.npy + labels.npy  (single file with side-car)

Labels are taken from the filename stem or directory name, whichever applies.

Usage
-----
    sudo python3 build_dataset.py [--dry-run] [--max-packets N]

    --dry-run       Inspect .npy files only; skip network setup (no root needed).
    --max-packets N Replay at most N packets per label (default: all).

Dependencies
------------
    pip install numpy pandas pyarrow pyshark
    apt install hostapd wpasupplicant tcpdump iw
"""

import os
import sys
import time
import socket
import signal
import shutil
import logging
import textwrap
import argparse
import subprocess
import threading
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
import pyshark

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser()
parser.add_argument("--dry-run",     action="store_true")
parser.add_argument("--max-packets", type=int, default=None, metavar="N")
ARGS = parser.parse_args()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR   = Path(__file__).parent.resolve()
OUTPUT_DIR   = SCRIPT_DIR / "dataset_output"
PCAP_DIR     = OUTPUT_DIR / "captures"
DATASET_FILE = OUTPUT_DIR / "dataset.parquet"

AP_IFACE  = "wlan0"
STA_IFACE = "wlan1"
MON_IFACE = "wlan2"

AP_SSID    = "dataset-ap"
AP_PASS    = "datasetpass1234"
AP_CHANNEL = 6
AP_IP      = "192.168.77.1"
STA_IP     = "192.168.77.2"

REPLAY_PORT  = 19999
REPLAY_DELAY = 0.0002
CAPTURE_TAIL = 3.0
BATCH_SIZE   = 200     # packets per TCP connection during replay

RSSI_MEAN   = -65.0
RSSI_SHADOW =  4.0
RSSI_FAST   =  1.5

HOSTAPD_CONF = "/tmp/ds_hostapd.conf"
WPASUP_CONF  = "/tmp/ds_wpa_supplicant.conf"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# .npy loading
# ---------------------------------------------------------------------------

def _normalise(arr: np.ndarray) -> np.ndarray:
    """
    Return a (N, L) uint8 array regardless of input dtype / layout.
    Handles: object arrays of variable-length lists, any integer dtype.
    """
    if arr.dtype == object:
        max_len = max(len(r) for r in arr)
        out = np.zeros((len(arr), max_len), dtype=np.uint8)
        for i, row in enumerate(arr):
            r = np.asarray(row, dtype=np.int32)
            n = min(len(r), max_len)
            out[i, :n] = np.clip(r[:n], 0, 255)
        return out
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    return np.clip(arr, 0, 255).astype(np.uint8)


def load_npy(path: Path) -> np.ndarray:
    """
    Load a single .npy file and return a (N, L) uint8 array.
    Handles both plain arrays (Layout A) and pickled dicts (Layout B).
    """
    raw = np.load(str(path), allow_pickle=True)

    # Layout B: np.save was called on a dict
    if raw.ndim == 0 and raw.dtype == object:
        d = raw.item()
        if isinstance(d, dict):
            for key in ("payload", "data", "x", "X", "bytes", "packet"):
                if key in d:
                    return _normalise(np.asarray(d[key]))
            # Fall back to first value that has >= 2 dims
            for v in d.values():
                v = np.asarray(v)
                if v.ndim >= 2:
                    return _normalise(v)
            raise ValueError(f"No usable array in dict keys: {list(d.keys())}")

    return _normalise(raw)


def discover_npy_files() -> Dict[str, Path]:
    """
    Return {label: path} for all discoverable label .npy files.
    Priority: ET-BERT tree → flat .npy files → dataset.npy + labels.npy.
    """
    found: Dict[str, Path] = {}

    # 1. ET-BERT tree
    tree_root = SCRIPT_DIR / "datasets" / "cstnet-tls1.3"
    if tree_root.exists():
        for label_dir in sorted(tree_root.iterdir()):
            if not label_dir.is_dir():
                continue
            for candidate in ("train.npy", "train_dataset.npy"):
                p = label_dir / candidate
                if p.exists():
                    found[label_dir.name] = p
                    break
            else:
                npy_list = sorted(label_dir.glob("*.npy"))
                if npy_list:
                    found[label_dir.name] = npy_list[0]

    # 2. Flat layout
    SKIP = {"labels", "dataset", "index"}
    for p in sorted(SCRIPT_DIR.glob("*.npy")):
        if p.stem not in SKIP:
            found[p.stem] = p

    # 3. Combined dataset.npy + labels.npy
    combined = SCRIPT_DIR / "dataset.npy"
    lbl_path  = SCRIPT_DIR / "labels.npy"
    if combined.exists() and lbl_path.exists() and not found:
        data    = load_npy(combined)
        labels  = np.load(str(lbl_path), allow_pickle=True)
        tmp_dir = OUTPUT_DIR / "_splits"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        for lbl in np.unique(labels):
            p = tmp_dir / f"{lbl}.npy"
            np.save(str(p), data[labels == lbl])
            found[str(lbl)] = p

    if not found:
        log.error(
            "No .npy files found. Expected one of:\n"
            "  • <label>.npy files next to this script\n"
            "  • datasets/cstnet-tls1.3/<label>/<split>.npy\n"
            "  • dataset.npy + labels.npy"
        )
        sys.exit(1)

    return found


def inspect_files(files: Dict[str, Path]) -> None:
    log.info("Discovered %d label(s):", len(files))
    for label, path in files.items():
        try:
            arr = load_npy(path)
            n   = arr.shape[0] if ARGS.max_packets is None else min(arr.shape[0], ARGS.max_packets)
            log.info("  %-30s  %d packets × %d bytes  (%s)",
                     label, n, arr.shape[1], path.name)
        except Exception as exc:
            log.error("  %-30s  LOAD ERROR: %s", label, exc)

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

def check_root() -> None:
    if os.geteuid() != 0:
        log.error("Needs root: sudo python3 build_dataset.py")
        sys.exit(1)

def check_deps() -> None:
    missing = [b for b in ("hostapd", "wpa_supplicant", "tcpdump", "iw", "ip")
               if not shutil.which(b)]
    if missing:
        log.error("Missing binaries: %s", ", ".join(missing))
        sys.exit(1)

def shell(cmd: str, check: bool = True) -> str:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{r.stderr.strip()}")
    return r.stdout.strip()

def wlan_interfaces() -> List[str]:
    out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
    return [l.split()[1] for l in out.splitlines() if l.strip().startswith("Interface")]

# ---------------------------------------------------------------------------
# Virtual network
# ---------------------------------------------------------------------------

_procs: List[subprocess.Popen] = []

def _bg(cmd: List[str], name: str) -> None:
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _procs.append(p)
    log.info("Started %s (pid=%d)", name, p.pid)

def start_network() -> None:
    # Load hwsim if needed
    if "mac80211_hwsim" not in subprocess.run(["lsmod"], capture_output=True, text=True).stdout:
        r = subprocess.run(["modprobe", "mac80211_hwsim", "radios=3"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            log.error("modprobe failed: %s", r.stderr.strip())
            sys.exit(1)
        time.sleep(1)

    ifaces = wlan_interfaces()
    for need in (AP_IFACE, STA_IFACE, MON_IFACE):
        if need not in ifaces:
            log.error("Interface %s not found. Got: %s", need, ifaces)
            sys.exit(1)

    # AP
    Path(HOSTAPD_CONF).write_text(textwrap.dedent(f"""\
        interface={AP_IFACE}
        driver=nl80211
        ssid={AP_SSID}
        hw_mode=g
        channel={AP_CHANNEL}
        wpa=2
        wpa_passphrase={AP_PASS}
        wpa_key_mgmt=WPA-PSK
        rsn_pairwise=CCMP
    """))
    shell(f"ip link set {AP_IFACE} up")
    shell(f"ip addr flush dev {AP_IFACE}")
    shell(f"ip addr add {AP_IP}/24 dev {AP_IFACE}")
    _bg(["hostapd", HOSTAPD_CONF], "hostapd")
    time.sleep(2)

    # Station
    Path(WPASUP_CONF).write_text(textwrap.dedent(f"""\
        ctrl_interface=/var/run/wpa_supplicant
        network={{
            ssid="{AP_SSID}"
            psk="{AP_PASS}"
            key_mgmt=WPA-PSK
        }}
    """))
    _bg(["wpa_supplicant", "-B", "-Dnl80211", f"-i{STA_IFACE}", f"-c{WPASUP_CONF}"],
        "wpa_supplicant")
    time.sleep(3)
    shell(f"ip addr flush dev {STA_IFACE}")
    shell(f"ip addr add {STA_IP}/24 dev {STA_IFACE}")
    shell(f"ip route add {AP_IP}/32 dev {STA_IFACE}", check=False)

    # Monitor
    shell(f"ip link set {MON_IFACE} down")
    shell(f"iw dev {MON_IFACE} set type monitor")
    shell(f"ip link set {MON_IFACE} up")
    shell(f"iw dev {MON_IFACE} set channel {AP_CHANNEL}")
    log.info("Network up  AP=%s  STA=%s  MON=%s", AP_IP, STA_IP, MON_IFACE)

def stop_network() -> None:
    for p in _procs:
        try:
            p.terminate(); p.wait(timeout=5)
        except Exception:
            p.kill()
    for iface in (AP_IFACE, STA_IFACE):
        shell(f"ip addr flush dev {iface}", check=False)
    shell(f"ip link set {MON_IFACE} down", check=False)
    shell(f"iw dev {MON_IFACE} set type managed", check=False)
    log.info("Network torn down")

# ---------------------------------------------------------------------------
# Echo server
# ---------------------------------------------------------------------------

def _drain(conn: socket.socket) -> None:
    conn.settimeout(2.0)
    try:
        while conn.recv(65536):
            pass
    except Exception:
        pass
    finally:
        conn.close()

def echo_server(stop: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((AP_IP, REPLAY_PORT))
    srv.listen(128)
    srv.settimeout(1.0)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
            threading.Thread(target=_drain, args=(conn,), daemon=True).start()
        except socket.timeout:
            pass
    srv.close()

# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

def replay(packets: np.ndarray) -> None:
    """
    Send each row of `packets` (uint8, N×L) as a TCP payload bound to STA_IP.
    The kernel TCP/IP stack + mac80211 + CCMP encryption do the rest.
    Packets are batched into connections of BATCH_SIZE to produce realistic
    flow sizes rather than one giant stream.
    """
    n = len(packets)
    for start in range(0, n, BATCH_SIZE):
        batch = packets[start : start + BATCH_SIZE]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.bind((STA_IP, 0))
            s.settimeout(5.0)
            s.connect((AP_IP, REPLAY_PORT))
            for row in batch:
                s.sendall(row.tobytes())
                time.sleep(REPLAY_DELAY)
            s.close()
        except Exception as exc:
            log.debug("Batch replay error: %s", exc)

# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

def capture_label(label: str, packets: np.ndarray) -> Path:
    out = PCAP_DIR / f"{label}.pcap"

    stop = threading.Event()
    t = threading.Thread(target=echo_server, args=(stop,), daemon=True)
    t.start()
    time.sleep(0.3)

    tcpdump = subprocess.Popen(
        ["tcpdump", "-i", MON_IFACE, "-w", str(out),
         "--snapshot-length=0", "-U",
         "not (type mgt subtype beacon)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.4)

    log.info("Replaying %d packets → label '%s'", len(packets), label)
    replay(packets)

    time.sleep(CAPTURE_TAIL)
    tcpdump.send_signal(signal.SIGINT)
    tcpdump.wait(timeout=10)
    stop.set()
    t.join(timeout=5)

    sz = out.stat().st_size if out.exists() else 0
    log.info("  capture: %s  (%d bytes)", out.name, sz)
    return out

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(pcap: Path, label: str) -> pd.DataFrame:
    log.info("Extracting features from %s", pcap.name)
    records = []
    cap = pyshark.FileCapture(
        str(pcap),
        display_filter="wlan.fc.type == 2",
        use_json=True,
    )
    prev_ts = None
    for pkt in cap:
        try:
            ts  = float(pkt.sniff_timestamp)
            iat = (ts - prev_ts) if prev_ts is not None else 0.0
            prev_ts = ts
            w  = pkt.wlan
            rt = getattr(pkt, "radiotap", None)
            records.append({
                "label"        : label,
                "timestamp"    : ts,
                "iat"          : float(iat),
                "frame_len"    : int(pkt.length),
                "fc_type"      : int(w.fc_type),
                "fc_subtype"   : int(w.fc_subtype),
                "fc_retry"     : int(getattr(w, "fc_retry", 0)),
                "fc_protected" : int(getattr(w, "fc_protected", 0)),
                "seq_num"      : int(getattr(w, "seq", 0)),
                "qos_tid"      : int(getattr(w, "qos_tid", 0)),
                "duration"     : int(getattr(w, "duration", 0)),
                "signal_dbm"   : float(getattr(rt, "dbm_antsignal", -30)),
                "data_rate"    : float(getattr(rt, "datarate", 0)),
                "mcs_index"    : int(getattr(rt, "mcs_index", 0)),
            })
        except Exception:
            continue
    cap.close()
    df = pd.DataFrame(records)
    log.info("  %d frames extracted", len(df))
    return df

# ---------------------------------------------------------------------------
# Augmentation
# ---------------------------------------------------------------------------

def augment(df: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    """
    Replace flat hwsim signal_dbm / mcs_index with a two-component RSSI model
    (per-flow shadowing + per-frame fast fading) and a MCS ladder.
    """
    rng = np.random.default_rng(seed)
    df  = df.copy()

    # Correlated shadowing: one offset per 200-frame block within each label
    df["_blk"] = (df.groupby("label").cumcount() // 200).astype(str)
    df["_fid"] = df["label"] + "_" + df["_blk"]
    shadow_map = {fid: rng.normal(0, RSSI_SHADOW) for fid in df["_fid"].unique()}
    shadow     = df["_fid"].map(shadow_map).to_numpy()
    fast       = rng.normal(0, RSSI_FAST, size=len(df))

    df["signal_dbm"] = (RSSI_MEAN + shadow + fast).clip(-90, -20).astype(np.float32)
    df.drop(columns=["_blk", "_fid"], inplace=True)

    rssi = df["signal_dbm"].to_numpy()
    df["mcs_index"] = np.select(
        [rssi >= -55, rssi >= -62, rssi >= -68,
         rssi >= -74, rssi >= -77, rssi >= -82, rssi >= -87],
        [7, 6, 5, 4, 3, 2, 1], default=0
    ).astype(np.int8)

    df["log_iat"]      = np.log1p(df["iat"]).astype(np.float32)
    df["frame_len_kb"] = (df["frame_len"] / 1024).astype(np.float32)
    return df

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("=" * 60)
    log.info("802.11 dataset builder — ET-BERT .npy source")
    log.info("=" * 60)

    npy_files = discover_npy_files()
    inspect_files(npy_files)

    if ARGS.dry_run:
        log.info("--dry-run: done. No network setup performed.")
        return

    check_root()
    check_deps()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)

    start_network()
    all_dfs: List[pd.DataFrame] = []

    try:
        for label, path in npy_files.items():
            packets = load_npy(path)
            if ARGS.max_packets:
                packets = packets[:ARGS.max_packets]
            log.info("Label '%s': %d × %d bytes", label, *packets.shape)

            pcap = capture_label(label, packets)
            df   = extract_features(pcap, label)
            if not df.empty:
                all_dfs.append(df)
    finally:
        stop_network()

    if not all_dfs:
        log.error("No features extracted — check pcap contents")
        sys.exit(1)

    dataset = augment(pd.concat(all_dfs, ignore_index=True))
    dataset.to_parquet(DATASET_FILE, index=False, compression="snappy")
    log.info("Saved: %s  shape=%s", DATASET_FILE, dataset.shape)
    log.info("Label distribution:\n%s", dataset["label"].value_counts().to_string())

    summary = dataset.groupby("label").agg(
        frames    = ("frame_len",  "count"),
        mean_len  = ("frame_len",  "mean"),
        mean_rssi = ("signal_dbm", "mean"),
        mean_mcs  = ("mcs_index",  "mean"),
    ).round(2)
    summary.to_csv(OUTPUT_DIR / "summary.csv")
    log.info("Summary written to %s/summary.csv", OUTPUT_DIR)


if __name__ == "__main__":
    main()