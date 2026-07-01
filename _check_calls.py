#!/usr/bin/env python3
import struct
import sys

path = sys.argv[1]
d = open(path, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]


def ro(r):
    n = struct.unpack_from("<H", d, pe + 6)[0]
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    sec = pe + 24 + opt
    for i in range(n):
        o = sec + i * 40
        vs, va, rsz, rp = struct.unpack_from("<IIII", d, o + 8)
        if va <= r < va + max(vs, rsz):
            return d[rp + (r - va):rp + (r - va) + 5]
    return b""


for r in (0x8AF4, 0x8CD4, 0x8C2B, 0x8DF1):
    b = ro(r)
    print(f"0x{r:X}: {b.hex()} {'E8' if b[:1]==b'\\xe8' else b[:2].hex()}")
