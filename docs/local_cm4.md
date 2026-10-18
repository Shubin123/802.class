# Local Mac + CM4 installation and validation

The Mac is the passive, channel-locked collector. The CM4 is a managed Wi-Fi
DUT. Both can build datasets and run CPU inference locally. Raw capture still
requires a supported monitor radio; installing the classifier does not turn a
single CM4 Wi-Fi radio into both DUT and independent collector.

## Install on the Mac

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e '.[dev,display]'
mkdir -p .tools
swiftc scripts/macos_monitor.swift -o .tools/macos-monitor
```

`wireshark-app` already installs the ChmodBPF
package. Homebrew therefore rejects installing the separate
`wireshark-chmodbpf` cask alongside it. Check actual access with:

```sh
id -Gn
dumpcap -i en0 -I -L
```

The account should belong to `access_bpf`; raw monitor output should list
`IEEE802_11_RADIO`. A fresh login/session may be necessary after group changes.
Do not uninstall the working Wireshark app to install its helper again.

## Capture with guaranteed cleanup attempts

On the tested Mac, associated-mode `dumpcap -I` and Apple `tcpdump -I` returned
zero packets. Disassociating and selecting the DUT frequency fixed this.
The helper briefly dedicates `en0` to capture, then verifies normal station
mode and autojoin. It power-cycles Wi-Fi if recovery stalls. Autojoin uses the
first saved network and macOS-stored credentials.
Ensure that first saved network is `James`:

```sh
networksetup -listpreferredwirelessnetworks en0
.venv/bin/python data/real/collect_ssh.py \
  --dut-host root@192.168.1.96 --security wpa2 \
  --label example_fetch --url https://example.com --sessions 3 --duration 20 \
  --prepare-monitor '.tools/macos-monitor {interface} {frequency}' \
  --restore-network '.tools/macos-monitor --restore {interface} James'
```

Cleanup runs in `finally`, including capture/preparation failures and ordinary
interrupts. A failed restore is an error. Recovery checks station mode, an
active link, a bound DHCP lease, and a successful HTTPS request. When macOS exposes the associated SSID,
recovery checks that it is `James`; recent macOS versions may redact that SSID.
In that case output explicitly states that exact SSID readback is unavailable.
SSH reconnects are retried after recovery. Keep the handheld awake throughout
collection, deployment, and testing.

Collect other labels using the same command with a different URL and label,
for example `python_fetch` / `https://www.python.org/`. These are scripted fetch
activities, not measurements of full native apps. The tool verifies PSK-only
RSN evidence for WPA2 or SAE-only evidence for WPA3, checks for DUT roaming,
and rejects unsuccessful traffic or captures without protected frames in both
directions. A WPA2/WPA3 transition-mode advertisement alone is insufficient to
prove a WPA3 association. Do not label WPA2 captures as WPA3.

```sh
.venv/bin/python data/build_field_dataset.py \
  --manifest data/field/cm4/manifest.csv --out data/field/cm4/dataset.parquet
.venv/bin/python scripts/evaluate_field.py
```

Evaluation splits whole source sessions before fitting. Reports and models stay
local under ignored `data/field/` and `models/`. The tiny single-DUT/AP trial
cannot establish application accuracy across devices, environments, or ciphers.

## Install and test independently on Lakka

```sh
.venv/bin/python scripts/deploy_cm4.py --host root@192.168.1.96 \
  --include-field-data --test
```

The installer uses writable `/storage/802.class`, a private virtual environment,
and CPU PyTorch wheels. The large CUDA requirements in `requirements.txt` are
for the legacy experiment and are not suitable for Lakka. The bundled legacy
archive is copied and extracted; it lacks field BSSID/session grouping.

The CM4 runs its own pytest suite and `scripts/verify_install.py`. That script
creates synthetic CCMP/GCMP frame envelopes, builds Parquet, trains baseline
and TCN models, exports ONNX, reloads checkpoints, and runs capture inference.
It performs no network requests. Its synthetic success is installation evidence,
not a live security or accuracy claim.

For real field data, rebuild the transferred manifest on the CM4 so dataset
capture paths refer to its own storage, then train and infer there:

```sh
ssh root@192.168.1.96
cd /storage/802.class
.venv/bin/python data/build_field_dataset.py \
  --manifest data/field/cm4/manifest.csv --out data/field/cm4/dataset.parquet
.venv/bin/python scripts/evaluate_field.py
```

All computation in those commands occurs on the CM4. A held-out inference
result is saved as `data/field/cm4/independent-inference.json`. If available,
systemd can demonstrate operation inside an isolated network namespace while
keeping the host Wi-Fi and SSH connection intact:

```sh
systemd-run --unit=wifi-classifier-offline-check --collect --wait --pipe \
  -p PrivateNetwork=yes -p WorkingDirectory=/storage/802.class \
  /storage/802.class/.venv/bin/python \
  /storage/802.class/scripts/verify_install.py --require-isolated-network
```

The verifier rejects the isolated-network claim unless it observes a distinct
Linux network namespace containing only the loopback interface. Its JSON report
records `network_isolated` and `network_interfaces`.

## Handheld UI

After deployment, run on the CM4:

```sh
cd /storage/802.class
.venv/bin/python scripts/install_lakka_ui.py --start
```

The framebuffer dashboard replaces RetroArch while open. It shows runtime
validation, real dataset windows/sessions, WPA2/WPA3 evidence, and the latest
classifier result. Controller button 0 starts the offline check, button 2 runs
local sample inference, and button 1 exits. When a real model/capture is absent,
the classify action uses the installed synthetic sample and model, explicitly
labeled as a demo. The UI also shows the legacy replay dataset’s local packet
and class counts after verification. The on-screen A/X/B labels assume
the common button mapping; the underlying joystick indices are explicit here.
Stopping the service also restores RetroArch:

```sh
systemctl stop wifi-classifier.service
```

The installer creates a `Wi-Fi Classifier` playlist entry using the existing
Bash Launcher core. The dashboard is not enabled as the default boot UI.
No browser, external web service, or Mac is needed to use the dashboard.
