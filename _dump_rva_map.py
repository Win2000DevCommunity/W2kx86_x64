"""Dump rva_map for cmd.exe translation (static-only, fast)."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from x86_x64 import PE32Image, DynamicScanResult, Win2000Translator

X86 = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"

data = open(X86, "rb").read()
pe = PE32Image(data)
tr = Win2000Translator(
    pe,
    dynamic_result=DynamicScanResult(),
    verbose=False,
    win10_test_shim=True,
    source_path=X86,
)
tr.translate()
for rva in [0x6314, 0x640E, 0x6578, 0x734A, 0x7350, 0x64BD, 0x89F6, 0x2D1B6, 0x2D1B8, 0x2CFF2]:
    off = tr.rva_map.get(rva)
    print(f"rva 0x{rva:X} -> off {off} ({hex(off) if off is not None else 'MISSING'})")

# find what old rva maps to shim 0x2D1B8
for old, off in sorted(tr.rva_map.items()):
    if off is not None and abs(off - 0x2D1B8) < 8:
        print(f"shim ~2D1B8 from old 0x{old:X} -> 0x{off:X}")
