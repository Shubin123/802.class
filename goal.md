# Project goal: application inference from raw 802.11 monitor-mode frames

## Mission

Build a clean end-to-end pipeline for a passive field device that infers
application-level activity from Wi-Fi traffic. The device captures raw IEEE
802.11 frames in monitor mode; the operator supplies the MAC address of the
router/access point of interest (its BSSID). The pipeline selects client-to-AP
and AP-to-client traffic belonging to that BSSID, separates it into sensible
client/session observations, and outputs an app-level classification.

The target input includes radiotap and 802.11 MAC/header information plus
encrypted protected-frame bodies. The field device does **not** possess WPA
keys, TLS session keys, IP reassembly, DNS, SNI, or decrypted payloads.

The system is for authorized measurement and research captures only. Preserve
privacy by minimizing retained identifiers and payload material; do not add
decryption, key capture, or techniques intended to bypass Wi-Fi encryption.

## Two-layer framing

1. **Packet/network-layer baseline (already explored):** CNN and Transformer
   models were evaluated on the CSTNET/ET-BERT TLS 1.3 dataset. At this layer,
   packet-level representations may implicitly expose or preserve DNS and other
   network-layer context. Results here are useful baselines, but are not evidence
   that a passive Wi-Fi monitor can make the same prediction.
2. **Raw 802.11 layer (current objective):** train a classifier directly on
   capture-native protected 802.11 frames, without IVs/keys and without
   decrypting or reconstructing higher layers. Given a target BSSID, it should
   identify the app/service/activity associated with each client↔AP observation
   from the observable traffic fingerprint.

The second layer is the product-relevant problem. Do not treat the first layer's
scores as deployable performance.

## Current repository context

- `data/data.py` replays CSTNET TLS 1.3 packet data through simulated Wi-Fi
  (`mac80211_hwsim`) and captures it; `data/databuilder.py` exports up to the
  first 256 bytes of each encrypted frame body.
- `train/` contains windowed packet-sequence 1D CNN/ResNet experiments.
- `infer/` reads monitor-mode PCAP/PCAPNG, currently filters data frames by a
  supplied MAC, and supports payload-byte or metadata inference. It must evolve
  to accept an AP/BSSID and correctly select traffic in both directions for its
  associated clients. `data/real/` contains a two-machine real-capture harness
  and `infer/eval_real.py` measures the simulated-to-real gap.
- The current real-data harness is a **two-device collection experiment**, not
  the intended field pipeline: a Windows DUT generates labeled traffic while a
  second machine listens/captures in monitor mode and coordinates the run. It
  was meant to isolate traffic while retaining an over-the-air view. It has not
  produced a reliable training setup: the capture may look isolated, but this
  constrained traffic does not necessarily contain enough representative
  variation or discriminative signal for the CNN/Transformer. Do not assume the
  data are sufficient merely because their labels are clean; measure signal,
  diversity, and generalization before using them for training claims.
- The simulated corpus and existing checkpoints are baselines only. Fabricated
  radio conditions and replay behavior make them unsuitable as final training
  evidence for field capture.

### Implementation assessment

- `data/data.py` currently replays TLS-dataset bytes through `mac80211_hwsim`,
  then synthesizes RSSI/MCS variation. This is useful for exercising the code
  path, but it cannot establish an over-the-air app fingerprint.
- Its feature dataset is frame-oriented (IAT, length, sequence, retry/QoS,
  duration, and selected radiotap fields). The current training loader forms
  fixed 128-frame windows by label and then randomly splits windows. It does not
  preserve capture-session/device/AP boundaries, so it is not a valid real-world
  evaluation protocol.
- The alternate payload path stores a fixed prefix of `data.data`. For protected
  frames this must be treated as an experimental opaque-byte input, not an
  application representation; it needs an explicit capture/parser contract and
  a real-data ablation against metadata-only features.
- The current inference filter accepts a MAC appearing in any 802.11 address
  field and largely restricts to plain data subtype `0x20`. That is a useful
  diagnostic, but not BSSID-scoped field inference. It lacks ToDS/FromDS-aware
  AP association, client-stream construction, deduplication/retry policy,
  sessioning, and an `unknown` result.

### Capture topology decision

Do not conflate the passive field observer with the device used to generate
labeled traffic. A monitor interface is passive-only and a monitor radio can
observe only its currently locked channel. The production field unit therefore
does **not** transmit Wi-Fi application traffic: it runs a monitor-capable radio
locked to the selected BSSID's channel and uses Ethernet, cellular, or a second
radio for management/backhaul if needed.

The default, reliable hardware layout is:

```
target clients  <--- Wi-Fi on target AP channel --->  target AP/BSSID
                         ^
                         | passive raw 802.11 monitor radio
                    field collector (native Linux)
                         |
                    Ethernet/cellular management
```

For dataset collection, use a physical DUT (preferably the device/OS that will
represent the target app), the target AP, and the collector above. Ground-truth
automation/logging belongs on the DUT or an out-of-band control path; it must
not be injected through the monitor radio.

A single computer can be a controlled **lab** DUT and collector only when it has
at least two independent physical Wi-Fi radios: one managed/client radio to
send real traffic through an existing AP and one monitor radio locked to that
AP channel. Keep Ethernet for control. Network namespaces can prevent local
routing shortcuts, but this setup is still a collection domain, not a substitute
for a physical mobile DUT. A full single-chassis AP + client + sniffer lab needs
three independent radios.

Linux may expose managed and monitor virtual interfaces on one physical radio,
but driver/firmware interface-combination support and channel constraints vary.
It is an optional diagnostic configuration only; it must pass a capture-quality
comparison against a separate monitor radio before it is used. A VM does not add
a radio chain: USB pass-through merely assigns a physical adapter to the guest.
Use a VM only if a specific DUT operating system requires it, with a separate
host monitor adapter; do not use virtualization to make one Wi-Fi adapter serve
both roles. `mac80211_hwsim` remains parser/test simulation only because its
virtual radios intentionally lack real hardware limitations.

## Constraints and threat model

- Input: passive monitor-mode PCAP/PCAPNG on the observed channel(s), plus a
  user-provided target BSSID/router MAC. Captures
  can be incomplete, noisy, interleaved across devices, and affected by channel
  changes, retransmissions, rate adaptation, power save, aggregation, and loss.
- Permitted information: capture timestamp/order, radiotap observations when
  available, 802.11 MAC/header fields, frame direction/type/subtype, protected
  frame length, sequence/retry indicators, and opaque encrypted-body length or
  bytes. Treat encrypted bytes as opaque; any usefulness must be demonstrated
  across independent captures rather than assumed.
- Excluded information: WPA/TLS keys, decrypted MSDUs, IP/TCP/UDP headers,
  DNS/SNI/HTTP metadata, traffic injected to provoke an answer, and labels or
  splits derived from those excluded features.
- The BSSID is the scope selector, not a class feature. Use 802.11 ToDS/FromDS
  addressing rules to associate frames with the selected AP and infer client
  peers. Treat multicast/broadcast, WDS, roaming, management, control, and
  ambiguous frames explicitly rather than silently assigning them to a client.
- A practical system must tolerate client MAC randomization and distinguish a
  device track/session from an application prediction. It must not rely on a
  fixed client MAC, AP, channel, capture host, or collection timestamp as an
  accidental label.

## Near-term work

1. Define the first supported app-level label taxonomy and unit of prediction
   (for example, an app/service session or a coarse activity category), including
   an `unknown` / abstain outcome.
2. Collect a real over-the-air dataset with capture manifests that record consent,
   label, app/version, device/OS, AP/channel/band, environment, session bounds,
   capture quality, and train/validation/test grouping keys. Use the existing
   real-capture harness only as a starting point, not as the final collection
   design. Replace or augment its isolated two-device runs with varied,
   repeatable app activity that includes sufficient sessions, timing/size
   variation, concurrent/background behavior, and network conditions to test
   whether a real app-level fingerprint exists.
3. Build the field pipeline: capture monitor-mode frames, accept `--bssid`, apply
   correct 802.11 address/DS-bit logic to select client↔AP data frames, derive
   per-client ordered observations, then extract features and classify each
   observation. Start with robust non-content features: direction, protected frame
   length, inter-arrival time, burst/window statistics, retry/sequence behavior,
   frame subtype, and available radiotap signal/rate/channel values. Version the
   schema and retain provenance.
4. Establish simple baselines before new deep models: length/timing features with
   logistic regression or tree models; then sequence CNN/Transformer models.
   Compare opaque-body-byte inputs against metadata-only inputs to determine
   whether byte features generalize or merely leak collection artifacts.
5. Evaluate by held-out capture sessions and, where possible, by device, AP,
   environment, and collection day. Report macro-F1, per-class precision/recall,
   confusion matrix, calibration/abstention behavior, and performance relative to
   chance. Never use a random packet/window split as the headline result.
6. Train and evaluate with roughly GTX 1080 Ti-class compute available; model
   capacity is no longer constrained to Coral-class edge limits. Explore models
   large enough to test the real signal (including sequence CNNs and
   Transformers), while retaining a compact candidate when accuracy permits.
   The preferred deployable candidate should export cleanly to ONNX and run in a
   browser through ONNX Runtime Web/WebGPU. Measure accuracy, latency, memory,
   model size, and short/partial-window behavior for both the best research model
   and the compact web-deployable model.

## Research-informed approach

The closest published analogue is [MACPrint](https://arxiv.org/abs/2408.07263):
it uses passive Wi-Fi MAC-layer traffic, sliding-window statistical/contextual
features, a temporal convolutional network, and open-world recognition. Its
reported results are encouraging, but its collection conditions and labels are
not this project's benchmark; reproduce the **methodological lessons**, not its
headline accuracy. Earlier work also demonstrates that timing and frame-size
side channels can reveal app behavior without Wi-Fi keys
([UCL study](https://discovery.ucl.ac.uk/1497081/)). These sources support a
metadata-first real-capture baseline and an explicit unknown/abstain policy.

The first model family should therefore be a compact temporal convolutional
network (TCN) over fixed, BSSID-scoped client windows, with a classical model on
window aggregates as the control. A larger Transformer is an experiment only
after that baseline is established. Do not start by training on encrypted body
bytes or by assuming the more complex model is better.

## Delivery plan and gates

### Phase 0 — specify the field contract

Write a short, versioned contract before implementation:

- **Input:** PCAP/PCAPNG or live monitor-mode stream, selected BSSID, capture
  interface/channel metadata, and optional capture time range.
- **Output:** per-client, per-observation-window `{known app label | unknown |
  insufficient data}`, confidence, window time bounds, frame count, and model /
  feature-schema version. Never produce one unsupported AP-wide app label.
- **Addressing:** derive client/AP direction from 802.11 ToDS/FromDS and BSSID
  rules; define handling for QoS data, four-address/WDS, multicast/broadcast,
  management/control frames, retransmissions, and fragmented/ambiguous frames.
- **Success gate:** a small hand-labeled PCAP fixture set proves correct frame
  inclusion, direction, client identity, ordering, and retry behavior.

### Phase 1 — make the capture and dataset real

Replace the current isolated trigger-run as the primary data source with a
collection protocol that records real app use and labels it at the source. For
each app/activity, collect multiple sessions across days, app versions,
devices/OS versions, APs, bands/channels, signal conditions, and background
traffic states. Keep a manifest with session and split-group IDs; the same
session, device, AP, or collection day must never be shared across train and
test when that dimension is being tested.

Include unknown apps and ordinary background/idle traffic from the beginning.
Capture-quality checks must record channel lock, dropped packets, radiotap field
availability, target-BSSID frame counts, client counts, and duplicate/retry
rates. The two-device harness may remain as a controlled label source, but its
data must be marked as one collection domain and never be the only test domain.

- **Success gate:** enough independent sessions exist to hold out at least one
  collection domain; a data report shows balanced labels, frame/window counts,
  capture quality, and no grouping overlap.

### Phase 2 — establish a reproducible feature baseline

Build one shared parser for training, offline evaluation, and live inference.
Its initial per-frame features should be direction, protected-frame length,
inter-arrival time, retry/sequence behavior, QoS TID, frame subtype, and only
the radiotap fields actually present in the capture. Derive window features such
as directional packet/byte counts, length histograms/quantiles, burst counts,
IAT statistics, and retry rate. Missing radiotap values must be represented as
missing, not synthesized.

Train a simple aggregate-feature baseline (logistic regression and/or gradient
boosted trees) before neural models. Then compare a small TCN over the ordered
features, plus a controlled opaque-byte ablation. Store feature names/order and
normalization statistics alongside every checkpoint.

- **Success gate:** all three paths emit byte-for-byte equivalent feature rows
  for fixture PCAPs, and a metadata-only baseline beats chance on held-out
  sessions before model complexity increases.

### Phase 3 — test generalization and open-world behavior

Report results under progressively harder grouped splits: held-out sessions,
then device, AP/environment, collection day, and unseen-app/background sets.
The headline score is per-observation or per-session macro-F1 with coverage and
false-accept rate for `unknown`, not random-window accuracy. Include confusion
matrices, calibration, short-window curves, and performance under packet loss.

- **Success gate:** the selected model improves materially over the classical
  baseline on multiple held-out domains, while keeping an acceptable unknown
  false-accept rate. Otherwise revisit labels/data/features rather than tuning a
  larger network.

### Phase 4 — package the field pipeline

Implement live/offline capture ingestion, BSSID selection, client/session state,
feature-window buffering, classification, and structured results. First ship the
accurate research model for 1080 Ti-class execution; then distill or retrain a
small static-shape TCN for ONNX. Validate export numerically against PyTorch and
benchmark ONNX Runtime Web with WebGPU plus a WASM fallback, since GPU operator
coverage is not universal ([ONNX Runtime Web documentation](https://onnxruntime.ai/docs/tutorials/web/)).

- **Success gate:** a recorded field PCAP produces the same output in offline
  and streaming modes; the ONNX model agrees with the reference model within a
  defined tolerance and has recorded browser latency/memory/coverage limits.

## Definition of progress

A claim is credible only when a model trained on real raw-802.11 captures beats
transparent baselines on strictly disjoint capture sessions and has been checked
for device/AP/environment leakage. Keep an experiment record containing the data
manifest version, feature-schema version, split rule, model/config/checkpoint,
metrics, and known limitations.

## Collaboration rules

- State whether work concerns the packet/network baseline or the raw-802.11
  layer. Do not silently transfer assumptions, features, or labels between them.
- Preserve raw captures and manifests as immutable inputs; write derived datasets
  and reports to versioned output locations.
- Make label mappings explicit. Existing CSTNET labels are numeric class IDs and
  training currently applies a lexicographic remapping; new datasets must ship a
  durable human-readable label map.
- Before optimizing accuracy, inspect data quality, capture coverage, class
  balance, and leakage. A high score on replayed or randomly split windows is a
  diagnostic, not a milestone.
- Keep inference and evaluation feature extraction identical, and add regression
  tests with representative PCAP fixtures whenever the feature contract changes.

## Open decisions

- Exact target labels: individual apps, services, website/application categories,
  or user activities.
- Observer placement and hardware/channel coverage expected of the field device.
- The exact output granularity: per client/window, per client session, or an AP
  aggregate; per-client/session is the default because multiple apps can be
  active behind one router at the same time.
- Minimum observation window and acceptable abstention rate for deployment.
- Dataset collection scale and the generalization dimensions required for the
  first defensible result.
- What collection protocol produces sufficient app-specific entropy and diversity
  without relying on artificial replay or overly isolated two-device traffic.
- The accuracy/latency/model-size trade-off required for the WebGPU/ONNX model
  relative to the larger 1080 Ti-class research model.
