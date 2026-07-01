#!/usr/bin/env python3
import struct
import sys

p = sys.argv[1]
target = int(sys.argv[2], 16)
d = open(p, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
n = struct.unpack_from("<H", d, pe + 6)[0]
sec = pe + 24 + opt
for i in range(n):
    o = sec + i * 40
    if d[o:o + 8].split(b"\0")[0] == b".text":
        tva, rsz, rp = struct.unpack_from("<III", d, o + 12)
        td = d[rp:rp + rsz]
        break
else:
    raise SystemExit("no .text")

for i in range(len(td) - 5):
    if td[i] == 0xE8:
        rel = struct.unpack_from("<i", td, i + 1)[0]
        dst = tva + i + 5 + rel
        if dst == target:
            print(f"call -> 0x{target:X} from rva=0x{tva + i:X}")
