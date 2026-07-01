#!/usr/bin/env python3
import struct
import pefile

pe = pefile.PE(r"..\win2000_x64\cmd_shim.exe", fast_load=True)
blob = pe.sections[0].get_data()
new_base = 0x80000000
shim_end = new_base + 0x01000000
pos = 0x3EDA0
begin, end = struct.unpack_from("<II", blob, pos + 4)
handler = struct.unpack_from("<I", blob, pos + 16)[0]
print(f"entry scope blob+{pos:#x}: begin={begin:#x} end={end:#x} handler={handler:#x}")
print(f"  shim_ok={(new_base <= begin < shim_end and new_base < end <= shim_end and begin < end)}")

n = 0
for i in range(0x3DD00, len(blob) - 19):
    if blob[i:i + 4] != b"\xff\xff\xff\xff":
        continue
    b, e = struct.unpack_from("<II", blob, i + 4)
    if not (new_base <= b < shim_end and new_base < e <= shim_end and b < e):
        continue
    h = struct.unpack_from("<I", blob, i + 16)[0]
    print(f"  valid scope blob+{i:#x} handler={h:#x}")
    n += 1
print(f"valid shim scopes: {n}")
