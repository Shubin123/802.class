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

## 1. Hardware / setup

- A WiFi adapter that supports **monitor mode** (e.g. Atheros AR9271,
  MediaTek MT7612U, or any mac80211 NIC that allows `type monitor`).
- A separate **device under test (DUT)** — phone/laptop — joined to your AP. Note
  its **client MAC** (this is the `mac` column in the manifest).
- Capture host on **the same channel** as the AP.

Put the capture adapter into monitor mode, locked to the AP's channel `N`:

```bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
sudo iw dev wlan1 set channel N        # N = your AP's channel (e.g. 36)
```

(Or use `airmon-ng start wlan1`, which creates `wlan1mon`.)

## 2. Collect — one service per timed window

For each service, with the DUT in a **fresh browser profile, extensions off, and
background chatter minimized**, load *only that service* for a fixed window:

```bash
sudo ./capture.sh wlan1mon 36 132 s01 60   # CSTNET id 132 (youtube), session s01, 60s
```

Repeat for several services and 2+ sessions each (sessions let the harness report
a per-session majority vote and, later, a session-disjoint split). Start with
**CDN-distinct** services (e.g. youtube / netflix / wikipedia / github) — many of
the 120 labels share CDNs (`cloudfront`, `azureedge`, `alicdn`, `amazonaws`,
`ggpht`, `twimg`…) and will be inherently confusable.

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
