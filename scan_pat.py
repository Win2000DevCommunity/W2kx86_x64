#!/usr/bin/env python3
import struct
import sys

p = sys.argv[1]
d = open(p, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
n = struct.unpack_from("<H", d, pe + 6)[0]
sec = pe + 24 + opt
for i in range(n):
    o = sec + i * 40
    vs, va, rsz, rp = struct.unpack_from("<IIII", d, o + 8)
    if d[o:o + 8].split(b"\0")[0] == b".text":
        td = d[rp:rp + rsz]
        tva = va
        break
else:
    raise SystemExit("no .text")

for pat, name in [
    (b"\x8b\x7d\x30", "mov edi,[rbp+0x30]"),
    (b"\x44\x8b\x4d\x40", "mov r9d,[rbp+0x40]"),
    (b"\x66\xc7\x00\x22\x00", "mov word [rax],0x22"),
]:
    idx = 0
    while True:
        i = td.find(pat, idx)
        if i < 0:
            break
        print(f"{name} rva=0x{tva + i:X}")
        idx = i + 1
