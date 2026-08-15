"""Pointer discovery / .data fixups must not clobber real slots."""
import pathlib
import struct
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from x86x64.analysis.discover import (
    discover_static_pointers,
    _looks_like_utf16le_dword,
    _plausible_image_pointer,
)
from x86x64.pe.fixups import fixup_data_section


def test_utf16_ascii_pair_is_detected():
    assert _looks_like_utf16le_dword(0x0043002e)  # ".C"
    assert _looks_like_utf16le_dword(0x00000000)
    assert not _looks_like_utf16le_dword(0x4ad010a8)


def test_pathext_bytes_are_not_pointer_sites():
    data = bytes.fromhex(
        "500041005400480045005800540000002e0043004f004d00")
    sites = discover_static_pointers(data, 0x1c6a8, 0x4ad00000, 0x30000)
    assert sites == set()


def test_small_integers_are_not_pointer_sites():
    # cmd.exe .data neighbourhood: size 0xa next to real VA pointer
    data = struct.pack("<IIII", 0x7a, 0xa, 0x4ad24320, 0)
    sites = discover_static_pointers(data, 0x1c8d0, 0x4ad00000, 0x48000)
    assert (0x1c8d0 + 0) not in sites  # 0x7a utf16-ish / too small
    assert (0x1c8d0 + 4) not in sites  # 0xa counter
    assert (0x1c8d0 + 8) in sites      # real image VA


def test_plausible_rejects_header_rvas():
    assert not _plausible_image_pointer(0xa, 0x4ad00000, 0x48000)
    assert not _plausible_image_pointer(1, 0x4ad00000, 0x48000)
    assert _plausible_image_pointer(0x4ad24320, 0x4ad00000, 0x48000)
    assert _plausible_image_pointer(0x1c8d8, 0x4ad00000, 0x48000)


def test_fixup_preserves_packed_pointers_and_widens_padded():
    old_base, new_base, image_size = 0x4ad00000, 0x80000000, 0x48000
    section_rva = 0x1c000
    # layout mirrors cmd .data+0x8d4.. : small, ptr(+pad0), ptr, code_ptr
    data = bytearray(0x20)
    struct.pack_into("<I", data, 0x00, 0xa)
    struct.pack_into("<I", data, 0x04, 0x4ad24320)
    struct.pack_into("<I", data, 0x08, 0)          # padding high half
    struct.pack_into("<I", data, 0x0c, 0x4ad1c378)
    struct.pack_into("<I", data, 0x10, 0x4ad097f3)
    out = fixup_data_section(
        bytes(data), section_rva, [], old_base, new_base, image_size, set(), {})
    # small int untouched
    assert struct.unpack_from("<I", out, 0x00)[0] == 0xa
    # padded pointer widened to qword under new_base (same RVA)
    assert struct.unpack_from("<Q", out, 0x04)[0] == new_base + 0x24320
    # packed adjacent DWORD pointers stay DWORD (not clobbered)
    assert struct.unpack_from("<I", out, 0x0c)[0] == new_base + 0x1c378
    assert struct.unpack_from("<I", out, 0x10)[0] == new_base + 0x097f3
