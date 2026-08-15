#!/usr/bin/env python3
"""One-off: run normalize on built cmd_shim and show entry scope handler."""
import struct
import sys

import pefile

# Import after pe load to avoid heavy translate
sys.path.insert(0, ".")
from x86_x64 import Win2000Translator  # noqa: E402

pe64 = pefile.PE(r"..\win2000_x64\cmd_shim.exe", fast_load=True)
blob = bytearray(pe64.sections[0].get_data())
pos = 0x3EDA0

t = Win2000Translator.__new__(Win2000Translator)
t.win10_test_shim = True
t.new_base = 0x80000000
t.old_base = 0x4AD00000
t._seh_eh3_handler_old_vas = set()
t._w2k_eh3_va = 0x18001010C0
t.pe = pefile.PE(
    r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe",
    fast_load=True,
)
t.pe.image_size = t.pe.OPTIONAL_HEADER.SizeOfImage
t._scope_table_out_ranges = [(0x3EDA0, 64)]

h0 = struct.unpack_from("<I", blob, pos + 16)[0]
print(f"before handler={h0:#x} sentinel_ok={t._valid_scope_sentinel(blob, pos)}")
fixed = t._normalize_scope_table_handlers(blob)
h1 = struct.unpack_from("<I", blob, pos + 16)[0]
print(f"fixed={fixed} after handler={h1:#x}")
