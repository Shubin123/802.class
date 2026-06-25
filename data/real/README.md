# Real-data test harness

The purpose of this directory is to **measure whether the current model transfers
to real traffic at all**, before investing in a re-haul. The model was trained
entirely on `mac80211_hwsim`-simulated data with fabricated radio features, so
the expectation is **~chance accuracy here**. Turning that expectation into a
measured number is the go/no-go gate for everything else.

You do **not** need the WPA key. We classify on frame *metadata*
(size / timing / direction / sequence), which is visible in monitor mode even
on encrypted (CCMP) traffic.

---

## 1. Roles & hardware

Two machines:

- **Sniffer = this MacBook.** Its built-in Wi-Fi (`en0`) goes into monitor mode
  while the Mac stays online over **Ethernet**. macOS monitor capture is reliable
  and emits radiotap — more so than a DWA-171 / RTL8812AU on Linux.
- **DUT (device under test) = a SEPARATE Wi-Fi device** (phone, or the Linux box
  as a plain client) joined to your AP. We classify *its* frames; note its
  **Wi-Fi MAC** → the `mac` column. The Mac cannot be both sniffer and DUT on one
  radio (monitor mode can't browse).

> ⚠️ **Ethernet must be the active default route BEFORE you enable monitor mode**,
> or the Mac drops offline (monitor mode disassociates Wi-Fi). On this machine,
> as last checked, `en0` (Wi-Fi) was the default route and the Ethernet adapters
> were inactive — fix that first:
>
> ```bash
> route -n get default | grep interface   # must NOT print en0
> ifconfig en3; ifconfig en4              # your Ethernet adapter: 'status: active' + an inet
> ```

## 2a. Collect on macOS (recommended)

`airport sniff` was removed in macOS 14.4+; we use Wireshark's `dumpcap`, which
sets monitor mode **and** channel on the built-in card. Express the AP's channel
as a frequency (ch157 = 5785 MHz; the repo's `c157.pcapng` suggests ch157).

For each service, with the DUT in a **fresh browser profile (extensions off,
background chatter minimized)**, load *only that service* for a fixed window:

```bash
sudo ./capture_mac.sh 117 s01 5785 60               # CSTNET id 117, session s01, ch157, 60s
# 80 MHz wide AP: sudo ./capture_mac.sh 117 s01 5785,VHT80,5775 60
```

Output → `sessions/117__s01.pcapng`. The script refuses to run if Wi-Fi is still
your default route, so it won't strand you offline.

**Channel width matters.** If your AP runs 80/160 MHz and you capture at 20 MHz,
you'll catch management/control frames but **miss most high-rate data frames** —
exactly the ones we classify. The `<type>` token (`VHT80`, `VHT160`, `HT40+`…) is
Wireshark-version-specific, so for wide channels the **GUI is the most reliable**:
open **Wireshark** → *Capture Options* → select `en0` → tick **Monitor Mode** →
set the 802.11 channel **and width** → record.

## 2c. Sanity-check before collecting the full set

Do one short test capture and confirm you actually got **data frames from the DUT
MAC** (not just beacons). This catches wrong-channel / wrong-width / wrong-MAC
before you waste a collection run:

```bash
TS=/Applications/Wireshark.app/Contents/MacOS/tshark
# total data frames (type 2) in the capture:
$TS -r sessions/117__s01.pcapng -Y 'wlan.fc.type==2' 2>/dev/null | wc -l
# data frames involving your DUT's Wi-Fi MAC:
$TS -r sessions/117__s01.pcapng -Y 'wlan.fc.type==2 && wlan.addr==<DUT_WIFI_MAC>' 2>/dev/null | wc -l
```

You want at least a few hundred data frames for the DUT MAC over a 60 s window.
A handful (or zero) means wrong channel/width/MAC — fix before continuing. The
harness needs ≥128 frames per capture to form even one window.

## 2b. Collect on Linux (alternative — the DWA-171 path)

```bash
sudo ip link set wlan1 down; sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up;   sudo iw dev wlan1 set channel 157
sudo ./capture.sh wlan1mon 157 117 s01 60
```

(The DWA-171 / RTL8812AU needs the morrownr/aircrack `8812au` driver and is often
flaky in monitor mode — which is why the Mac path above is preferred.)

Then, regardless of OS: repeat for several services and **2+ sessions each**
(sessions enable a per-session majority vote and, later, a session-disjoint
split). Start with **CDN-distinct** services — many of the 120 labels share CDNs
(`cloudfront`, `azureedge`, `alicdn`, `amazonaws`, `ggpht`, `twimg`…) and are
inherently confusable.

## 2d. Automated, clock-synced collection (use this for training data)

A capture is only usable as training data if every frame maps to one known service.
`collect.py` guarantees that: it starts the capture **and** commands the DUT to load
exactly one service for a fixed window, so the file↔service mapping is correct by
construction. With `--transport agent` the two devices keep a synced clock, and each
traffic window is recorded **in the sniffer's clock** (the pcap clock) in the manifest.

No SSH, no keys — control is a **plain TCP socket on the LAN**. Two DUT options:

| where it runs | file | role |
|---|---|---|
| both | `sync.py` | control protocol (length-prefixed JSON) + NTP-style clock-offset estimation |
| **DUT** (synced) | `dut_agent.py` | recommended: takes `generate` commands, **reports exact start/stop** so windows are millisecond-accurate (`--transport agent`) |
| **DUT** (simplest) | `dut_listen.sh` | zero-Python: a `netcat` listener that runs the pushed command (`--transport nc`). No clock sync — orchestrator brackets the window |
| sniffer | `collect.py` | one-command orchestrator: capture + drive DUT + manifest |
| DUT (opt) | `dut_browse.py` | headless-browser traffic (`--traffic playwright`); needs `pip install playwright && playwright install chromium` |

### Topology (both devices have Wi-Fi + Ethernet on one network)
- **Control = Ethernet.** Point `--dut-host` at the DUT's **Ethernet IP** so control
  traffic never enters the Wi-Fi capture.
- **Traffic = Wi-Fi.** Same-subnet means the OS may send "browse" traffic out Ethernet;
  the `curl` driver forces Wi-Fi with `curl --interface <wlan>`. On a **Linux DUT run
  `dut_agent.py` as root** so curl hard-binds the device (`SO_BINDTODEVICE`). The
  post-capture data-frame count is your proof egress actually went over Wi-Fi.

### Step 1 — on the DUT (pick one; both are keyless)
```bash
# A) synced, recommended:
python3 dut_agent.py --port 9999 --wifi-iface wlan0     # Linux: prefix with sudo;  macOS: --wifi-iface en0

# B) zero-Python netcat (lab LAN only — it runs pushed commands via sh):
./dut_listen.sh 9999                                    # GNU-traditional nc: NC_PFLAG=1 ./dut_listen.sh 9999
```

### Step 2 — one command on the sniffer
```bash
# Rehearse the sync + RPC + timing with NO capture (safe; works even over loopback):
python collect.py --services services.example.csv --transport agent \
    --dut-host <DUT_ETH_IP> --no-capture --sessions 1 --duration 3

# Real run (Ethernet must be the Mac's default route — collect.py refuses otherwise):
sudo python collect.py --services services.csv --transport agent \
    --dut-host <DUT_ETH_IP> --dut-wifi-mac aa:bb:cc:dd:ee:ff --dut-wifi-iface wlan0 \
    --freq 5785 --sessions 3 --duration 60 --eval
```

`--eval` runs `eval_real.py` on the fresh manifest. Use **≥2 sessions**: distinct
sessions are what enable a leakage-free **session-disjoint** split later. (The current
synthetic model scores 93% on its own data but ~entirely via window-adjacency leakage —
permutation importance: scrambling the zero-information `seq_num` counter drops it to 1%.
A session-disjoint split removes that.)

For the **netcat** path, just swap `--transport agent` → `--transport nc` (same
`--dut-host`/`--dut-port`); `--transport local` is single-host testing. The manifest
gains `t_start,t_end` columns (sniffer clock); `eval_real.py` ignores them.

## 3. Label mapping (important — get this right or the gap number is meaningless)

Two gotchas:

1. **Model index ≠ CSTNET id.** Training did `sorted(df['label'].unique())` on
   *string* labels, so the model's output indices are the **lexicographic** sort
   of `"0".."119"` (e.g. CSTNET id `117` → model index `21`). The manifest
   `label` column should hold the **CSTNET class id** as a string;
   `eval_real.py` applies the same remap. (Or pass `--label-mode index` if your
   manifest already holds raw model indices.)

2. **The domain→id mapping is NOT settled in this repo.** The row-wise list in
   `../readme.md` contains `None`s and duplicates and appears to list *more than
   120 names*, so do **not** trust it blindly. The authoritative mapping is
   whatever `y_train` integers in your `.npy` source correspond to — confirm it
   there before trusting any accuracy number. The example manifest uses
   placeholder ids `0..3`; replace them with the verified ids for the services
   you actually capture.

## 4. Manifest

Copy `manifest.example.csv` to `manifest.csv` and fill it in:

```
pcap,mac,label,session
sessions/132__s01.pcap,aa:bb:cc:dd:ee:ff,132,s01
```

- `pcap`    — path relative to this manifest
- `mac`     — the **DUT client MAC** whose data frames to classify
- `label`   — CSTNET class id (string)
- `session` — optional group id for the per-session vote

## 5. Run the harness

```bash
python ../../infer/eval_real.py \
    --manifest manifest.csv \
    --checkpoint ../../train/checkpoints/best_resnet.pt.600epoch \
    --out report.json
```

It reports **window top-1, macro-F1, session top-1**, plus a **1/N chance
baseline** and a **majority-class baseline**, then prints a verdict. Near chance
⇒ the model does not transfer (expected) ⇒ proceed to the re-haul: retrain on
real data with size/direction/timing-sequence features.

> Note: `best_resnet.pt.300epoch/.600epoch` do **not** end in `.pt`, so the
> checkpoint must be passed explicitly (the harness handles this).
