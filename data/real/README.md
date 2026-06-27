# Real-data capture — Windows DUT + Mac sniffer

Goal: measure whether the model trained on synthetic (hwsim-replayed) data works on
**real** Wi-Fi traffic. Expectation: ~chance — which is the justification to retrain on
real data. This directory is the smallest path to that measured number.

## Roles (no monitor mode on the DUT)
- **DUT = Windows machine.** A *normal* Wi-Fi client with internet. It just browses the
  services; it never enters monitor mode. It has Wi-Fi **and** Ethernet, so traffic is
  forced out Wi-Fi (`curl --interface <wifi-ip>`).
- **Sniffer = the Mac.** `en0` in monitor mode on the AP's channel, capturing the DUT's
  frames over the air. Stays online via Ethernet so monitor mode doesn't drop it.

No SSH/relay/agent: the DUT runs **autonomously** and logs timestamps; the Mac captures
continuously and slices by those timestamps. Clocks just need to be NTP-synced.

## Flow

### 1. DUT (Windows) — get Wi-Fi info
```
git pull
python data\real\dut.py --info
```
Paste the `IFACE / WIFI_IP / WIFI_MAC / CHANNEL / FREQ` lines to the Mac side.

### 2. Mac — start capturing (needs Wireshark's ChmodBPF so dumpcap runs without sudo)
```
dumpcap -i en0 -I -k <FREQ> -w capture.pcapng        # leave running for the whole DUT run
```
(Ethernet must be the Mac's default route first, or monitor mode drops it offline.)

### 3. DUT (Windows) — run the schedule
```
python data\real\dut.py            # cycles services.csv over Wi-Fi, writes dut_run.csv
```
Send the printed schedule (or `dut_run.csv`) back.

### 4. Mac — slice + evaluate
```
python data/real/slice.py --pcap capture.pcapng --schedule dut_run.csv --mac <WIFI_MAC> --eval
```
This cuts per-service pcaps into `sessions/`, writes `manifest.csv`, and runs
`eval_real.py` for the real top-1 / macro-F1 vs the `1/N` chance baseline.

## Files
| file | runs on | role |
|---|---|---|
| `dut.py` | Windows DUT | autonomous traffic generator + Wi-Fi info |
| `services.csv` | — | `label,name,url` to browse (labels are CSTNET class ids) |
| `slice.py` | Mac | slice the capture by `dut_run.csv` + MAC → `manifest.csv` → eval |
| `../../infer/eval_real.py` | Mac | windowed prediction vs chance baseline |

## Notes
- **Labels** in `services.csv` must be the real CSTNET class ids for the gap number to be
  meaningful; the current values are provisional. (Model output index ≠ CSTNET id — the
  training remap is lexicographic; `eval_real.py` handles it.)
- If a sliced file shows **0–few data frames**: wrong channel, wrong MAC, or the DUT's
  traffic egressed Ethernet instead of Wi-Fi (check `--wifi-ip`).
- Many of the 120 classes share CDNs (cloudfront/azureedge/alicdn/…) — a size/timing
  fingerprint has a real collision ceiling regardless.
