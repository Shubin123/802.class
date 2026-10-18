# Raw 802.11 application classifier

This repository is moving from a TLS/replay experiment to a capture-native
pipeline that classifies **BSSID-scoped client observation windows** from raw
802.11 monitor-mode traffic. It does not decrypt Wi-Fi or TLS traffic.

The product statement is deliberately narrow: given an AP radio MAC/BSSID and
a channel-locked monitor capture, report whether each client window is
consistent with a known app/activity, `unknown`, or `insufficient_data`.

See [goal.md](goal.md) for the project direction and
[capture architecture](docs/capture_architecture.md) for the hardware decision.

## Important topology

The field unit is passive: a dedicated monitor radio captures the target AP's
channel and does not transmit target traffic. Use Ethernet/cellular/a second
radio for control. For labeled collection, use a physical DUT plus AP plus
passive collector. A VM does not give one Wi-Fi adapter an additional radio
chain.

## New pipeline

The new code is independent from the old simulator/checkpoints:

| Component | Purpose |
| --- | --- |
| `wifi_app/contract.py` | BSSID/DS-bit scoping, client sessions, versioned metadata schema |
| `wifi_app/capture.py` | PCAP/PCAPNG → canonical raw 802.11 observations |
| `data/capture_monitor.py` | Passive `dumpcap` wrapper for field capture |
| `data/build_field_dataset.py` | Manifest-driven real-capture dataset builder |
| `train/train_field.py` | Grouped aggregate baseline or compact TCN training/export |
| `infer/field_inference.py` | BSSID-scoped offline inference and BSSID discovery |

The existing `data/data.py`, `train/train.py`, and `infer/inference.py` are
legacy replay/TLS-baseline work. They are not used by the field pipeline.

## Local installation and CM4

See [local Mac + CM4 setup](docs/local_cm4.md) for portable installation, SSH DUT
collection, automatic return to the saved James Wi-Fi network, independent CM4
validation, and the handheld framebuffer UI. Use `pyproject.toml` or
`requirements-field.txt` for the field pipeline; the CUDA-pinned
`requirements.txt` belongs to the legacy experiment.

## Workflow

1. Confirm that the supplied address is the AP's **BSSID/radio MAC**, discover
   its channel, and place a supported monitor adapter on that channel.

2. Capture passively (only use `--set-channel` after proving that adapter/OS
   support it; otherwise configure monitor mode/channel outside the wrapper):

   ```powershell
   python data/capture_monitor.py --interface mon0 --out data/field/capture.pcapng `
     --duration 120 --bssid aa:bb:cc:dd:ee:ff --no-monitor
   ```

3. Inspect BSSID beacons in the result:

   ```powershell
   python infer/field_inference.py --pcap data/field/capture.pcapng --list-bssids
   ```

4. Create a manifest from
   [`data/field_manifest.template.csv`](data/field_manifest.template.csv). Every
   source session needs a unique `session_id`; record device/AP/environment/day
   so grouped evaluation is possible.

5. Build a real, protected-frame metadata dataset:

   ```powershell
   python data/build_field_dataset.py --manifest data/field_manifest.csv `
     --out data/field/dataset.parquet
   ```

6. Establish the classical control first, then train the compact TCN:

   ```powershell
   python train/train_field.py --data data/field/dataset.parquet `
     --model baseline --out models/field_baseline.joblib

   python train/train_field.py --data data/field/dataset.parquet `
     --model tcn --out models/field_tcn.pt --export-onnx models/field_tcn.onnx
   ```

7. Classify a capture using an explicitly BSSID-scoped model:

   ```powershell
   python infer/field_inference.py --pcap data/field/capture.pcapng `
     --bssid aa:bb:cc:dd:ee:ff --checkpoint models/field_tcn.pt `
     --out data/field/result.json
   ```

The build/train tools refuse important invalid states: absent BSSID/labels,
insufficient grouped examples per class, cross-group validation leakage, schema
mismatches, or no usable client windows.

## Validation

See the [hardware validation record](docs/validation.md) for observed results
and the remaining live WPA3 / physical UI checks.

```powershell
python -m pytest -q
```

The suite covers BSSID address semantics, QoS data, retry scope, per-client
sessioning, schema/padding, grouped splitting, PCAP-to-inference round trips,
and a grouped training/ONNX-export smoke path. It does not claim real-world
accuracy; that remains blocked on authorized, labeled monitor-mode data.

## Wireshark Extension

The classifier integrates directly with Wireshark and TShark via a native Lua postdissector, GUI tools menu, and Extcap capture interface.

```sh
.venv/bin/python scripts/install_wireshark_extension.py
```

This registers:
- **Display filters**: `wifi_app`, `wifi_app.prediction`, `wifi_app.direction`, `wifi_app.confidence`, `wifi_app.protected`, `wifi_app.client`, `wifi_app.bssid`.
- **Packet details**: Automatic 802.11 Data frame decoration with real-time sliding window predictions.
- **GUI Tools**: `Tools -> Wi-Fi App Classifier` for batch PCAP classification, beacon BSSID discovery, selected packet audits, and engine status.
- **Extcap Live Capture**: `802.11 Application Classifier Live Capture` interface in Wireshark.

See [Wireshark extension documentation](docs/wireshark_extension.md) for full details.

