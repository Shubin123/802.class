# Wi-Fi Application Classifier — Wireshark Extension

This extension integrates the capture-native 802.11 application classifier directly into Wireshark and TShark on macOS and Linux.

It operates without decrypting WPA2/WPA3 payloads or TLS streams. It inspects unencrypted 802.11 MAC headers, radiotap physical parameters, frame timing, and sequence deltas to classify BSSID-scoped client activity windows.

---

## Capabilities

| Component | Type | Location | Role |
| --- | --- | --- | --- |
| `wifi_app_classifier.lua` | Lua Postdissector | `~/.local/lib/wireshark/plugins/` | Decorates 802.11 data frames with application labels, confidence, direction, and session IDs |
| GUI Menu Tools | Wireshark GUI | `Tools -> Wi-Fi App Classifier` | Batch PCAP inference, beacon discovery, frame audit, and engine benchmarks |
| `wifi_app_capture` | Extcap Plugin | `~/.local/lib/wireshark/extcap/` | Adds a custom capture interface in Wireshark for live channel capture or PCAP replay |
| `wifi_app_helper.py` | Python Bridge | `wireshark/wifi_app_helper.py` | Standalone CLI linking Wireshark to PyTorch TCN and Scikit-Learn baseline models |

---

## Installation

Run the automated installer from the repository root:

```sh
.venv/bin/python scripts/install_wireshark_extension.py
```

The installer:
1. Exports baseline model weights to `models/active_model.json` for high-speed Lua dissection.
2. Symlinks `wifi_app_classifier.lua` into Wireshark's personal plugins directory (`~/.local/lib/wireshark/plugins/` and `~/.config/wireshark/plugins/`).
3. Symlinks `wifi_app_capture` into Wireshark's extcap directory (`~/.local/lib/wireshark/extcap/`).
4. Runs a verification pass using `tshark` on synthetic 802.11 captures.

To verify installation at any time:

```sh
.venv/bin/python scripts/install_wireshark_extension.py --status
```

To remove the extension:

```sh
.venv/bin/python scripts/install_wireshark_extension.py --uninstall
```

---

## Display Filters

Use these filters in Wireshark's display filter bar or with `tshark -Y`:

| Filter | Type | Description | Example |
| --- | --- | --- | --- |
| `wifi_app` | Boolean | Matches any classified 802.11 infrastructure data frame | `wifi_app` |
| `wifi_app.direction` | String | Frame direction relative to target BSSID | `wifi_app.direction == "uplink"` |
| `wifi_app.client` | String | Client station MAC address | `wifi_app.client == "02:00:00:00:00:11"` |
| `wifi_app.bssid` | String | Target access point radio MAC | `wifi_app.bssid == "f4:ca:e7:84:da:29"` |
| `wifi_app.protected` | Boolean | True for WPA2 (CCMP) and WPA3 (SAE/GCMP) protected frames | `wifi_app.protected == true` |
| `wifi_app.prediction` | String | Predicted application or activity class | `wifi_app.prediction == "fixture_large"` |
| `wifi_app.confidence` | Float | Model confidence score (0.00 to 1.00) | `wifi_app.confidence >= 0.70` |
| `wifi_app.qos_tid` | Integer | 802.11e QoS Traffic Identifier (0..15) | `wifi_app.qos_tid == 3` |
| `wifi_app.session_id` | String | Scoped client session track ID | `wifi_app.session_id` |

### TShark Example

```sh
tshark -r capture.pcapng \
  -Y 'wifi_app.direction == "uplink" && wifi_app.confidence >= 0.50' \
  -T fields -e frame.number -e wifi_app.client -e wifi_app.prediction -e wifi_app.confidence
```

---

## Wireshark GUI Menu Tools

Available under `Tools -> Wi-Fi App Classifier`:

### 1. 🎯 Classify Current Capture File
Runs the BSSID-scoped model pipeline on the active capture. Discovers BSSIDs, sessions client frames into 15-second tracks, evaluates 64-frame sliding windows, and displays:
- Session summary (client MAC, frame count, predicted app, confidence percentage)
- Window breakdown with start and end timestamps
- Unknown rejection statistics based on the calibrated threshold
- Automatically updates packet list columns and tree annotations with model predictions

### 2. 📡 Discover BSSIDs & Channels
Scans all 802.11 beacons in the loaded capture, reporting:
- BSSID radio MAC
- Advertised SSID (network name)
- Beacon frame counts
- Observed operating radio frequencies (MHz)

### 3. 🔍 Audit Selected Packet & Session
Inspects the currently selected packet in the Wireshark GUI packet list:
- Computes the client station and access point direction
- Displays the client's current accumulated frame track
- Shows the real-time feature extraction vector and confidence breakdown

### 4. ⚡ Classifier Status & Benchmarks
Displays runtime diagnostics in a Wireshark dialog:
- Active Python engine and PyTorch acceleration (Apple Silicon MPS / CUDA / CPU)
- Loaded TCN checkpoint and baseline weights
- CM4 DUT connectivity over SSH
- WPA2/WPA3 envelope and cipher support status

---

## Live Capture Extcap Interface

In Wireshark's welcome screen and interface list, the extension provides:
**`802.11 Application Classifier Live Capture` (`wifi_app_live`)**

Clicking the options gear icon enables configuring:
- **Capture Interface**: Local monitor adapter (default `en0`)
- **Channel Frequency (MHz)**: 2.4 GHz, 5 GHz, or 6 GHz channels (e.g. `2412`, `5220`, `5805`)
- **Target AP BSSID**: Radio MAC of the AP to monitor
- **Classification Engine**: Compact TCN (`tcn`) or Logistic Baseline (`baseline`)
- **Replay Capture File**: Optional path to replay an existing PCAP stream into Wireshark
