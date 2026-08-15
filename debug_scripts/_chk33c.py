import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

raw = pathlib.Path("build_univ33/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", raw, 0x3C)[0]
n = struct.unpack_from("<H", raw, e + 6)[0]
opt = struct.unpack_from("<H", raw, e + 20)[0]
s0 = e + 24 + opt
for i in range(n):
    o = s0 + i * 40
    name = raw[o : o + 8].split(b"\x00")[0]
    vsz, va, rsz, rp = struct.unpack_from("<IIII", raw, o + 8)
    if name.startswith(b".text"):
        text = raw[rp : rp + rsz]
        text_rva = va
    if name.startswith(b".data"):
        data = raw[rp : rp + min(rsz, vsz)]
        data_rva = va
        print("data rva", hex(va), "rsz", hex(rsz))

rmap = {}
rev = {}
for ln in pathlib.Path("build_univ33/rva.txt").read_text().splitlines():
    a = ln.split()
    x, y = int(a[0], 16), int(a[1], 16)
    rmap[x] = y
    rev[y] = x

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("==== 14DD1 ====")
for insn in md.disasm(text[0x14DC0 - text_rva : 0x14E00 - text_rva], 0x14DC0):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")

best = None
for y, x in rev.items():
    if y <= 0x14DD1 and (best is None or y > best[0]):
        best = (y, x)
print("nearest x86", hex(best[1]), "at", hex(best[0]))
print("b186", hex(rmap.get(0xB186, 0)))

# Check if 0x4AD20C00 appears as imm in .text or as data init
needle = struct.pack("<I", 0x4AD20C00)
print("old VA in text", text.find(needle))
print("old VA in data", data.find(needle) if data else None)
# rebased form
needle2 = struct.pack("<Q", 0x80060C00)  # if data at 5d000: 0x20c00-0x1c000=0x4c00 -> 0x5d000+0x4c00=0x61c00
# compute: orig RVA 0x20C00, data old 0x1C000, offset 0x4C00
# new data 0x5D000 + 0x4C00 = 0x61C00 -> VA 0x80061C00
print("expect rebased", hex(0x80000000 + 0x5D000 + (0x20C00 - 0x1C000)))
off = 0x20C00 - 0x1C000
print("data at off", hex(off), data[off:off+16].hex() if off < len(data) else "oob")
