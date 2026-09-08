import ast
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
            encoding = "latin-1"
        elif major in (2, 3):
            header_len = struct.unpack("<I", f.read(4))[0]
            encoding = "utf-8" if major == 3 else "latin-1"
        else:
            return f"Unsupported version {major}.{minor}"

        # NumPy headers are Python-literal dictionaries.  Do not execute them:
        # inspection tools may be pointed at captures from outside the project.
        header_str = f.read(header_len).decode(encoding)
        try:
            return ast.literal_eval(header_str)
        except (SyntaxError, ValueError):
            return header_str


def main():
    for d in ["flow_500", "packet_5000"]:
        print(f"=== {d} ===")
        if not os.path.exists(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.endswith(".npy"):
                path = os.path.join(d, f)
                print(f"  {f:30s} {read_npy_header(path)}")


if __name__ == "__main__":
    main()
