#!/usr/bin/env python3
import struct
import sys

d = open(sys.argv[1], "rb").read()
rva = int(sys.argv[2], 16)
n = int(sys.argv[3], 16)
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
ns = struct.unpack_from("<H", d, pe + 6)[0]
sec = pe + 24 + opt
for i in range(ns):
    o = sec + i * 40
    vs, va, rsz, rp = struct.unpack_from("<IIII", d, o + 8)
    if va <= rva < va + max(vs, rsz):
        off = rp + (rva - va)
        print(d[off:off + n].hex(" "))
        break
