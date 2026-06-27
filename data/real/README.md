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

## Run

### DUT (Windows) — start the ncat listener
```
git pull
data\real\ncat.exe -k -l 9999 --sh-exec "powershell -NoProfile -Command -"
```
Leave it running. Make sure `wlan` is connected to the AP. Note the **Ethernet IPv4**
(`ipconfig` → Ethernet adapter) — that's `--dut-host`.

### Mac — collect (you run this; `sudo` for dumpcap)
```
git pull
# 1) validate comms first — detects the DUT Wi-Fi and drives traffic, no capture:
python3 data/real/collect_ncat.py --dut-host <DUT_ETH_IP> --dut-port 9999 --no-capture --sessions 1 --duration 5
# 2) the real run:
sudo python3 data/real/collect_ncat.py --dut-host <DUT_ETH_IP> --dut-port 9999 --sessions 2 --duration 60
```
Auto-detects the DUT's Wi-Fi iface / IP / MAC / channel over ncat, captures + drives each
service, writes `sessions/*.pcapng` + `manifest.csv`. (Pass `--wifi-mac/--freq/--wifi-ip`
to override if detection is partial.)

### Evaluate
`infer/eval_real.py` reads `manifest.csv` and reports real top-1 / macro-F1 vs the `1/N`
chance baseline (needs torch/scapy — run it wherever those are installed, or hand the
`sessions/` + `manifest.csv` off for eval).

## Files
| file | runs on | role |
|---|---|---|
| `collect_ncat.py` | Mac | drives the DUT over ncat + captures + manifest |
| `ncat.exe` | Windows DUT | the listener binary (committed so no install) |
| `services.csv` | — | `label,name,url` (labels are CSTNET class ids) |
| `../../infer/eval_real.py` | — | windowed prediction vs chance baseline |

## Notes
- **Labels** in `services.csv` must be the real CSTNET class ids for the gap number to
  mean anything (provisional now). Model index ≠ CSTNET id; `eval_real.py` handles the remap.
- A capture with **0–few data frames** → wrong channel/MAC, or curl egressed Ethernet
  instead of Wi-Fi (pass `--wifi-ip <addr>`).
- Many of the 120 classes share CDNs → a size/timing fingerprint has a collision ceiling.
