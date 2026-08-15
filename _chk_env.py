import pathlib
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

base = pathlib.Path("build_univ30")
raw = (base / "cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", raw, 0x3C)[0]
n = struct.unpack_from("<H", raw, e + 6)[0]
opt = struct.unpack_from("<H", raw, e + 20)[0]
s0 = e + 24 + opt
for i in range(n):
    o = s0 + i * 40
    name = raw[o : o + 8].split(b"\x00")[0]
    vsz, va, rsz, rp = struct.unpack_from("<IIII", raw, o + 8)
    if name.startswith(b".text"):
        break
text = raw[rp : rp + rsz]
text_rva = va
rev = {}
for ln in (base / "rva.txt").read_text().splitlines():
    a = ln.split()
    x, y = int(a[0], 16), int(a[1], 16)
    rev[y] = x

md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(text[0x9E60 - text_rva : 0x9E60 - text_rva + 100], 0x9E60):
    best = None
    for y in range(insn.address, max(insn.address - 32, 0), -1):
        if y in rev:
            best = rev[y]
            break
    mark = hex(best) if best is not None else "?"
    print(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}  <- x86 {mark}")
    if insn.address > 0x9EC0:
        break
