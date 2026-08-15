import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

src = pathlib.Path(
    r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
).read_bytes()
e = struct.unpack_from("<I", src, 0x3C)[0]
n = struct.unpack_from("<H", src, e + 6)[0]
opt = struct.unpack_from("<H", src, e + 20)[0]
s0 = e + 24 + opt
for i in range(n):
    o = s0 + i * 40
    name = src[o : o + 8].split(b"\x00")[0]
    vsz, va, rsz, rp = struct.unpack_from("<IIII", src, o + 8)
    if name.startswith(b".text"):
        blob = src[rp : rp + rsz]
        tva = va
        break
md = Cs(CS_ARCH_X86, CS_MODE_32)
print("==== full e846 ====")
for insn in md.disasm(blob[0xE846 - tva :], 0xE846):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0xE8A0:
        break

# translated continuation after push 0x409
raw = pathlib.Path("build_univ31/cmd_pure.exe").read_bytes()
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
        break
md64 = Cs(CS_ARCH_X86, CS_MODE_64)
print("==== translated 2400 full ====")
for insn in md64.disasm(text[0x2400 - text_rva : 0x2400 - text_rva + 120], 0x2400):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0x2480:
        break

# Who is at x86 that maps near 2400?
rmap = {}
rev = {}
for ln in pathlib.Path("build_univ31/rva.txt").read_text().splitlines():
    a = ln.split()
    x, y = int(a[0], 16), int(a[1], 16)
    rmap[x] = y
    rev[y] = x
for y in range(0x23F0, 0x2480):
    if y in rev:
        print(f"  map {hex(y)} <- x86 {hex(rev[y])}")

# find_sane for e846 - check if real body exists elsewhere
print("search for movabs 80063874 patterns / cmp 3a4")
# original e846 pattern: load 22874, cmp 3a4
