# Validation record — 2026-10-18

This records observed results, including remaining gaps.

| Check | Result |
| --- | --- |
| Mac portable editable install and dependency consistency | Passed |
| Mac test suite | 20 passed |
| Lakka / CM4 writable installation | `/storage/802.class`, Python 3.11.13, PyTorch 2.14.1+cpu |
| CM4 test suite at the first deployed snapshot | 18 passed |
| CM4 offline capture/build/train/export/reload/inference | Passed: baseline and TCN, 36 synthetic windows / 12 source sessions |
| Real two-device WPA2 capture | Observed protected DUT traffic in both directions; one run had 2,377 protected frames and 48 successful interface-bound HTTPS fetches |
| Grouped real-activity classifier evaluation | Pending additional accepted labeled sessions |
| Live WPA3-SAE validation | Pending an authorized SAE test AP; current AP advertises PSK only |
| UI render preview | Passed locally; physical framebuffer/launcher validation pending |
| Final Mac network state during the interruption | Station mode, DHCP, HTTPS 200; first saved network `James` |

The synthetic CCMP/GCMP envelope tests establish parsing and inference plumbing.
They do not authenticate to an AP or verify ciphertext cryptographically.
The offline fixture's accuracy scores are not real-application accuracy.

The CM4 went to sleep before the final UI installation and field evaluation.
Those steps require waking the box and keeping it awake. Captures and datasets
are kept outside Git; the associated labels/quality must be validated before
including a capture in a real evaluation manifest.

macOS redacts associated SSID readback in this environment. The recovery target
is the first saved network, `James`; station mode, bound DHCP, and HTTPS access
can be verified independently. Exact associated SSID readback remains unavailable.
