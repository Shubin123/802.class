
import sys, socket, time
import numpy as np
try:
    packets = np.load('/home/shub/Desktop/torchit/802.class/data/dataset_output/tmp_replay.npy')
    for start in range(0, 4000, 200):
        batch = packets[start:start+200]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(5.0)
        s.connect(('192.168.77.1', 19999))
        for row in batch:
            s.sendall(row.tobytes())
            time.sleep(0.0002)
        s.close()
except Exception as e:
    print(f"Batch replay error: {e}", file=sys.stderr)
