# Validation record — 2026-10-18

This records observed results, including remaining gaps.

| Check | Result |
| --- | --- |
| Mac portable editable install and dependency consistency | Passed |
| Mac test suite | 25 passed |
| Lakka / CM4 writable installation | `/storage/802.class`, Python 3.11.13, PyTorch 2.14.1+cpu |
| CM4 test suite at the current deployed snapshot | 25 passed |
| CM4 offline capture/build/train/export/reload/inference | Passed: baseline and TCN, 36 synthetic windows / 12 source sessions |
| Real two-device WPA2 capture | Observed protected DUT traffic in both directions; one run had 2,377 protected frames and 48 successful interface-bound HTTPS fetches |
| Grouped real-activity classifier evaluation | Pending additional accepted labeled sessions |
| Live WPA3-SAE validation | Pending an authorized SAE test AP; current AP advertises PSK only |
| CM4 UI installation/display | Service and Lakka playlist installed; rendered output verified by framebuffer readback at 640×480 |
| CM4 UI return to Lakka | Stopping the dashboard restarted RetroArch successfully |
| CM4 local classify action | Passed: loaded its local TCN/sample and produced three prediction windows; labeled synthetic demo |
| CM4 isolated-network pipeline | Passed under systemd `PrivateNetwork=yes`; distinct network namespace, only `lo` present |
| Bundled dataset installed on CM4 | 944,687 packet rows / 120 classes; legacy replay provenance |
| Final Mac network state during the interruption | Station mode, DHCP, HTTPS 200; first saved network `James` |

The synthetic CCMP/GCMP envelope tests establish parsing and inference plumbing.
They do not authenticate to an AP or verify ciphertext cryptographically.
The offline fixture's accuracy scores are not real-application accuracy.

The UI and standalone installation checks were completed after the CM4 woke.
The isolated-network test performed capture parsing, dataset building, baseline
and TCN training, ONNX export, checkpoint reload, and inference on the CM4.
It isolated only the test process; neither device’s Wi-Fi connection was changed.

Grouped real-data evaluation and live WPA3 validation remain pending. No new
monitor capture or network reconfiguration was attempted during the follow-up
work. Captures and datasets stay outside Git; associated labels/quality must
be validated before including a capture in a real evaluation manifest.

macOS redacts associated SSID readback in this environment. The recovery target
is the first saved network, `James`; station mode, bound DHCP, and HTTPS access
can be verified independently. Exact associated SSID readback remains unavailable.
