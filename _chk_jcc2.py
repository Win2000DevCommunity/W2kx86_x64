from pathlib import Path

rmap={}
for line in Path("build_univ16/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b

for r in (0xb719, 0xb71f, 0xb723, 0xb9c3, 0xb9dd, 0xb704):
    print(hex(r), "->", hex(rmap[r]) if r in rmap else "MISSING")

# How many jcc targets around this function are missing?
# From disasm, targets b9c3, b9dd, b790
for r in range(0xb790, 0xba00):
    if r in rmap:
        pass
print("b790", hex(rmap.get(0xb790,0)), "b9c3", hex(rmap.get(0xb9c3,0)), "b9dd", hex(rmap.get(0xb9dd,0)))

# Count how many pe sites still have 0f00 in univ15 vs univ16
import struct
for label in ("univ15","univ16"):
    data=Path(f"build_{label}/cmd_pure.exe").read_bytes()
    e=struct.unpack_from("<I", data, 0x3c)[0]
    soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
    num=struct.unpack_from("<H", data, e+6)[0]
    for i in range(num):
        o=sec+i*40
        if data[o:o+5]==b".text":
            vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
            text=data[rp:rp+rs]; break
    print(label, "broken jcc", text.count(b"\x0f\x00\x00\x00\x00\x00"))
