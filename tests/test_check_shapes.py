import importlib.util
import struct
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "data" / "check_shapes.py"
SPEC = importlib.util.spec_from_file_location("check_shapes", MODULE_PATH)
check_shapes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_shapes)


def write_npy_header(path: Path, header: str, version=(1, 0)):
    encoded = header.encode("latin-1")
    length = struct.pack("<H", len(encoded)) if version[0] == 1 else struct.pack("<I", len(encoded))
    path.write_bytes(b"\x93NUMPY" + bytes(version) + length + encoded)


def test_read_npy_header_parses_standard_literal(tmp_path):
    path = tmp_path / "valid.npy"
    write_npy_header(path, "{'descr': '<u1', 'fortran_order': False, 'shape': (2, 3), }")

    assert check_shapes.read_npy_header(path) == {
        "descr": "<u1",
        "fortran_order": False,
        "shape": (2, 3),
    }


def test_read_npy_header_does_not_execute_header_code(tmp_path):
    marker = tmp_path / "executed.txt"
    path = tmp_path / "malicious.npy"
    write_npy_header(path, f"__import__('pathlib').Path({str(marker)!r}).write_text('owned')")

    assert check_shapes.read_npy_header(path).startswith("__import__")
    assert not marker.exists()
