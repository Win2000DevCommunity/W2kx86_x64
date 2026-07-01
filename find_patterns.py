#!/usr/bin/env python3
"""Find key RVAs in cmd_shim .text by byte pattern."""
import struct
import sys

p = sys.argv[1]
lo = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
hi = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0xFFFFFFFF

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

PATS = [
    (b"\x66\xc7\x00\x22\x00", "mov word [rax],0x22"),
    (b"\x48\x8d\x04\x5f", "lea rax,[rdi+rbx*2]"),
    (b"\x48\x8d\x3c\x47", "lea rdi,[rdi+rax*2]"),
    (b"\x8b\x45\x20", "mov eax,[rbp+0x20]"),
    (b"\x48\x89\xc3", "mov rbx,rax"),
    (b"\x48\x89\x04\x0a", "mov [rdx+rcx],rax qword"),
    (b"\x48\x8b\x3c\x08", "mov rdi,[rax+rcx] qword"),
    (b"\x44\x8b\x4d\x40", "mov r9d,[rbp+0x40]"),
    (b"\x4989\xc0", "mov r8,rax"),
    (b"\x4829\xd8", "sub rax,rbx"),
]

for pat, name in PATS:
    idx = 0
    while True:
        i = td.find(pat, idx)
        if i < 0:
            break
        rva = tva + i
        if lo <= rva <= hi:
            print(f"{name} rva=0x{rva:X}")
        idx = i + 1
