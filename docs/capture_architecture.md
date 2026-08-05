# Capture architecture

## Decision

Use a native-Linux field collector with a dedicated monitor-capable Wi-Fi radio.
It listens passively on the selected BSSID's channel; it does not transmit target
traffic. Keep management/backhaul on Ethernet, cellular, or a separate Wi-Fi
radio.

This is the simplest topology that faithfully matches the product:

```
                   monitor radio, locked to target channel
                              |
                              v
  client A ----\          field collector
  client B -----+-- AP ---------------- Internet
  client C ----/     ^
                   supplied BSSID
```

The classifier consumes the collector's capture, scopes frames to the supplied
BSSID, then creates per-client observation windows. A browser/WebGPU client can
run the classifier over sanitized windows or uploaded PCAPs, but it is not the
monitor-mode capture component.

## Why a single radio is not the baseline

A monitor interface is passive: it cannot be the transmitter for test traffic.
Some Linux drivers can expose managed and monitor virtual interfaces on the same
physical PHY, but their allowed interface combinations are driver-specific and
usually share a channel. Drivers can also omit locally transmitted frames or
radiotap fields in ways that harm the timing/size contract. Validate `iw list`,
then compare against a separate monitor-radio capture before relying on this
mode. It is a diagnostic convenience, not a field requirement.

Channel hopping is incompatible with a clean app-fingerprint trace: a monitor
radio observes one channel at a time, so hopping loses portions of bursts and
inter-arrival timing. Discover the BSSID, confirm its channel from beacons, and
lock the capture radio before collecting a labeled session.

## Training collection topologies

### Preferred: physical DUT + AP + passive collector

Use a phone/tablet/computer that actually runs the target app as the DUT. It
joins a normal AP. A separate collector radio listens in monitor mode. Ground
truth comes from authorized DUT-side automation or a companion logger over USB,
Ethernet, or another out-of-band path.

Advantages: representative app stack, realistic Wi-Fi association/rate control,
and no assumption that the collector can see its own transmission.

### Controlled single-chassis lab: two Wi-Fi radios + existing AP

When only one computer is available, use:

- Radio A in managed/station mode, associated with an existing AP, to generate
  ordinary browser or test-client traffic.
- Radio B in monitor mode, locked to that AP's channel, to capture it.
- Ethernet/cellular for control so capture does not drop the host offline.

Place Radio A in a network namespace if needed so the test client genuinely
egresses Wi-Fi rather than taking a loopback/local shortcut. Treat output as one
collection domain and hold it out from physical-DUT evaluation.

### Full single-chassis WLAN lab: three radios

Run a software AP on Radio A, a managed DUT on Radio B, and monitor on Radio C.
This is useful for reproducible parser and capture tests. It does not replace an
existing-router field capture because the AP, NICs, driver, and traffic source
are controlled by the same host.

### VM guidance

A VM is not a solution to radio concurrency. USB pass-through gives the guest
exclusive control of a physical Wi-Fi adapter; it does not create a second RF
chain. A VM is justified only when a target operating system/application must
run in it. In that case, assign one physical adapter to the guest for managed
Wi-Fi and retain a **different** host adapter for monitor capture. Prefer a
physical DUT for app fingerprint collection.

## Existing repository mapping

- `data/data.py` is the hwsim three-virtual-radio lab. It should remain legacy
  parser/replay infrastructure only. hwsim has deliberately idealized virtual
  radios and cannot validate the real capture model.
- `data/real/collect_ncat.py` is already close to the preferred two-machine
  topology: Windows is a managed Wi-Fi DUT and the Mac is monitor-mode sniffer
  with out-of-band Ethernet control. Its collection logic needs the new BSSID
  manifest fields, richer ground truth, and more representative activity—not a
  VM replacement.
- The new `wifi_app` package is capture-source neutral. It accepts offline
  PCAP/PCAPNG first so the same parser can serve both real collected captures
  and a future live capture process.

## Hardware acceptance checklist

Before collecting model data, record and verify:

1. The supplied address is a radio BSSID observed in beacons, not a router's
   Ethernet/base MAC.
2. The monitor adapter/driver exposes raw 802.11 headers and radiotap on the
   target band/channel.
3. The capture is channel-locked for the whole labeled session.
4. A known DUT produces both uplink and downlink protected QoS/data frames at
   the collector, with sensible retry rate and no persistent drop warnings.
5. The collector's control plane remains out of the monitored Wi-Fi path.
6. If same-PHY managed+monitor is attempted, a two-radio reference capture
   establishes that frame counts, direction mix, and timing are acceptable.

## References

- [Linux Wireless: monitor mode and virtual interfaces](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html)
- [Linux Wireless: monitor mode is passive-only](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw/vif.html)
- [Wireshark WLAN capture setup](https://wiki.wireshark.org/CaptureSetup/WLAN)
- [Linux Wireless: mac80211_hwsim](https://wireless.docs.kernel.org/en/latest/en/users/drivers/mac80211_hwsim.html)
