Base dataset is the cstnet-tls1.3
https://drive.google.com/drive/folders/1JSsYmevkxQFanoKOi_i1ooA6pH3s9sDr (get the flow dataset) (put in this (./data) directory)
https://github.com/linwhitehat/ET-BERT/tree/main/datasets

"""
build_dataset.py
================
End-to-end pipeline for generating a WPA-encrypted 802.11 monitor-mode
dataset from CSTNET-TLS 1.3 pcap files.

Phases
------
1. Validate kernel environment (mac80211_hwsim, hostapd, wpa_supplicant)
2. Bring up virtual AP (wlan0), station (wlan1), and monitor interface (wlan2)
3. Extract per-label TCP flows from CSTNET pcap files
4. Replay each flow through wlan1 (real kernel TCP → mac80211 → CCMP)
5. Capture 802.11 frames on wlan2 with label metadata
6. Extract features from labeled pcaps via pyshark
7. Augment synthetic RSSI / MCS with realistic distributions
8. Save final dataset to Parquet

Usage
-----
    sudo python3 build_dataset.py

Must be run as root (hostapd, wpa_supplicant, tcpdump, iw all require it).
CSTNET-TLS 1.3 pcap files must be in the same directory as this script.

Dependencies
------------
    (python)
    pip install scapy pyshark numpy pandas pyarrow
    (linux)
    pacman -S hostapd wpasupplicant tcpdump iw
    

CSTNET pcap naming convention expected
---------------------------------------
    cstnet_<label>.pcap   e.g.  cstnet_youtube.pcap
                                cstnet_zoom.pcap
                                cstnet_ssh.pcap
    Any pcap matching cstnet_*.pcap in the script directory is processed.
"""

![alt text](image.png)

