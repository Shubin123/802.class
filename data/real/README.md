# Real-data capture — Mac sniffer drives a Windows DUT over ncat

Goal: measure whether the model trained on synthetic (hwsim-replayed) data works on
**real** Wi-Fi traffic (expectation: ~chance → justifies retraining on real data).

## How it works (real two-machine comms, no SSH, nothing pasted by hand)
`collect_ncat.py` runs **on the Mac**. Over **ncat** it talks to an ncat listener on the
**Windows DUT** and, per (service, session):

```
start dumpcap on en0  ->  ncat-send a curl.exe-over-Wi-Fi loop to the DUT for the window
->  stop dumpcap  ->  count the DUT's data frames  ->  manifest row
```

Capture + trigger are one process on the Mac, so they share the Mac's pcap clock — that
**is** the sync — and `manifest.csv` is built here automatically.

- **DUT = Windows**, normal Wi-Fi client (never monitor mode). Has Wi-Fi + Ethernet, so
  curl is bound to the Wi-Fi IP (`--interface`) and **control (ncat) uses the Ethernet IP**
  so it stays out of the capture.
- **Sniffer = the Mac**, `en0` monitor mode on the DUT's AP channel, online via Ethernet.

## Run — two scripts

### Script 1 — DUT (Windows): `dut_listen.bat`
```
git pull
data\real\dut_listen.bat
```
Starts the ncat listener and prints this PC's IPs. Leave the window open. Make sure
`wlan` is connected to the AP, and allow port 9999 in the firewall (it tells you how).
Use one of the printed IPs as `--dut-host` on the Mac.

### Script 2 — Mac: `collect_ncat.py`
```
git pull
# 1) test comms only — detects the DUT Wi-Fi + drives traffic, no capture, no sudo:
python3 data/real/collect_ncat.py --dut-host 10.0.0.61 --no-capture

# 2) the real run — capture + drive each service (sudo for dumpcap):
sudo python3 data/real/collect_ncat.py --dut-host 10.0.0.61 --iface en0 --no-monitor --sessions 2 --duration 60
```
`--dut-host` is the only required flag (port defaults to 9999). It auto-detects the DUT's
Wi-Fi iface / IP / MAC / channel over a **single persistent ncat stream**, captures + drives
each service, and writes `sessions/*.pcapng` + `manifest.csv`.

**macOS monitor mode:** `dumpcap` can't set the 802.11 channel on macOS (`-k` errors), so
put the capture interface into **monitor mode on the AP's channel yourself** (the run prints
the channel — here ch44/5220), then pass `--no-monitor` so the collector just captures on it
as-is. If a capture shows few/0 frames, the interface is on the wrong channel or the MAC
filter is off (override with `--wifi-mac`).

### Evaluate
`infer/eval_real.py` reads `manifest.csv` and reports real top-1 / macro-F1 vs the `1/N`
chance baseline (needs torch/scapy — run it wherever those are installed, or hand the
`sessions/` + `manifest.csv` off for eval).

## Files
| file | runs on | role |
|---|---|---|
| `dut_listen.bat` | Windows DUT | **script 1** — starts the ncat listener |
| `collect_ncat.py` | Mac | **script 2** — drives the DUT + captures + manifest |
| `ncat.exe` | Windows DUT | the listener binary (committed so no install) |
| `services.csv` | — | `label,name,url` (labels are CSTNET class ids) |
| `../../infer/eval_real.py` | — | windowed prediction vs chance baseline |

## Notes
- **Labels** in `services.csv` must be the real CSTNET class ids for the gap number to
  mean anything (provisional now). Model index ≠ CSTNET id; `eval_real.py` handles the remap.
- A capture with **0–few data frames** → wrong channel/MAC, or curl egressed Ethernet
  instead of Wi-Fi (pass `--wifi-ip <addr>`).
- Many of the 120 classes share CDNs → a size/timing fingerprint has a collision ceiling.

## Linux / CM4 DUT over SSH (capture-native pipeline)

Use `collect_ssh.py` for Linux DUTs. The Mac remains the passive sniffer and the
CM4 remains a managed Wi-Fi client. Set up the portable local environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements-field.txt
```

The bundled legacy dataset can be extracted with
`unzip -n data/dataset_output_old/dataset.parquet.zip -d data/dataset_output_old`.
It is replay data without the field pipeline's session/BSSID grouping; do not
use it as evidence of WPA2/WPA3 field accuracy.

The Mac account needs BPF access (Wireshark ChmodBPF), a monitor-capable radio,
and the DUT's channel. Check `dumpcap -i en0 -I -L` first. Then run one labeled
activity at a time, collecting independent sessions for each class:

```sh
.venv/bin/python data/real/collect_ssh.py \
  --dut-host root@192.168.1.96 --interface en0 \
  --security wpa2 --label example_fetch --url https://example.com \
  --sessions 3 --duration 30
```

The collector records AP RSN evidence and rejects mismatched security modes.
For WPA3 use an SAE-only test AP and `--security wpa3`. A transition-mode beacon
does not establish which authentication the DUT negotiated. No passwords are
read or stored. Collection does not reconfigure the AP or DUT network.

SSH schedules detached, interface-bound curl traffic, then closes before the
Mac capture starts. SSH reconnects after capture to verify curl success. This
keeps control traffic outside the captured interval even when control uses
Wi-Fi. Capture channel support must still be verified from the resulting PCAP.
Only captures with successful traffic, no curl failures, and at least 16
protected DUT frames enter the manifest. Quality sidecars retain failed runs.
URL-fetch labels describe scripted activity, not native application behavior.

After collecting at least two activities with multiple sessions in both modes:

```sh
.venv/bin/python data/build_field_dataset.py \
  --manifest data/field/cm4/manifest.csv --out data/field/cm4/dataset.parquet
.venv/bin/python train/train_field.py --data data/field/cm4/dataset.parquet \
  --model baseline --folds 3 --out models/cm4_baseline.joblib
```

`security` is retained as dataset metadata, not a classifier feature. Evaluate
held-out sessions separately for WPA2 and WPA3 before claiming support or
accuracy. The synthetic CCMP/GCMP envelope tests check protected-frame parsing
and inference plumbing only; they do not perform authentication, cryptographic
verification, or live radio validation.

For the tested Mac, use the channel preparation and mandatory James Wi-Fi /
internet recovery commands in [local CM4 setup](../../docs/local_cm4.md).
The same guide covers the standalone CM4 runtime and handheld UI.
