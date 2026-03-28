import numpy as np
import os
import struct

def read_npy_header(filename):
    with open(filename, "rb") as f:
        magic = f.read(6)
        if magic != b"\x93NUMPY":
            return "Not a valid .npy file"
        major, minor = struct.unpack("<bb", f.read(2))
        if major == 1:
            header_len = struct.unpack("<H", f.read(2))[0]
        elif major == 2:
            header_len = struct.unpack("<I", f.read(4))[0]
        else:
            return f"Unsupported version {major}.{minor}"
        header_str = f.read(header_len).decode("ascii")
        try:
            return eval(header_str)
        except:
            return header_str

for d in ["flow_500", "packet_5000"]:
    print(f"=== {d} ===")
    if not os.path.exists(d): continue
    for f in sorted(os.listdir(d)):
        if f.endswith(".npy"):
            path = os.path.join(d, f)
            print(f"  {f:30s} {read_npy_header(path)}")
