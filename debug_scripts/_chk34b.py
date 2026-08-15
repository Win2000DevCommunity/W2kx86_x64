import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

raw = pathlib.Path("build_univ34/cmd_pure.exe").read_bytes()
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
        data = raw[rp : rp + rsz]
        data_rva = va

rmap = {}
rev = {}
for ln in pathlib.Path("build_univ34/rva.txt").read_text().splitlines():
    a = ln.split()
    x, y = int(a[0], 16), int(a[1], 16)
    rmap[x] = y
    rev[y] = x

md = Cs(CS_ARCH_X86, CS_MODE_64)
for addr in (0x28913, 0x14CD4):
    best = None
    for y, x in rev.items():
        if y <= addr and (best is None or y > best[0]):
            best = (y, x)
    print(f"==== {hex(addr)} x86~{hex(best[1])} ====")
    for insn in md.disasm(text[addr - 30 - text_rva : addr - text_rva + 40], addr - 30):
        print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")

# data at 674e0
off = 0x674E0 - data_rva
print("data 674e0", data[off:off+32].hex() if 0 <= off < len(data) else "oob")
try:
    print(" utf16", data[off:off+32].decode("utf-16-le", errors="replace"))
except Exception as ex:
    print(ex)
off2 = 0x5D1C0 - data_rva
print("data 5d1c0", data[off2:off2+16].hex())
print(" utf16", data[off2:off2+16].decode("utf-16-le", errors="replace"))
