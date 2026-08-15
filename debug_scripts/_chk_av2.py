import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

base = pathlib.Path("build_univ31")
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
        text = raw[rp : rp + rsz]
        text_rva = va
        break
rmap = {}
rev = {}
for ln in (base / "rva.txt").read_text().splitlines():
    a = ln.split()
    x, y = int(a[0], 16), int(a[1], 16)
    rmap[x] = y
    rev[y] = x

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("==== at 0x2400 ====")
for insn in md.disasm(text[0x2400 - text_rva : 0x2400 - text_rva + 80], 0x2400):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0x2450:
        break

# e846 mapping
print("e846", hex(rmap.get(0xE846, 0)))
print("==== e846 translated ====")
t = rmap.get(0xE846, 0)
if t:
    for insn in md.disasm(text[t - text_rva : t - text_rva + 60], t):
        print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
        if insn.address > t + 50:
            break

# What calls jump to 5d1c0?
print("==== search call/jmp to 5d1c0 or load of that VA ====")
needle = struct.pack("<Q", 0x8005D1C0)
idx = 0
hits = 0
while hits < 10:
    j = text.find(needle, idx)
    if j < 0:
        break
    print("imm hit at", hex(text_rva + j))
    idx = j + 1
    hits += 1

# Also check original e846
src = pathlib.Path(
    r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
).read_bytes()
e2 = struct.unpack_from("<I", src, 0x3C)[0]
n2 = struct.unpack_from("<H", src, e2 + 6)[0]
opt2 = struct.unpack_from("<H", src, e2 + 20)[0]
s02 = e2 + 24 + opt2
for i in range(n2):
    o = s02 + i * 40
    name = src[o : o + 8].split(b"\x00")[0]
    vsz, va, rsz, rp = struct.unpack_from("<IIII", src, o + 8)
    if name.startswith(b".text"):
        blob = src[rp : rp + rsz]
        tva = va
        break
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("==== x86 e846 ====")
for insn in md32.disasm(blob[0xE846 - tva : 0xE846 - tva + 80], 0xE846):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic == "ret" or insn.address > 0xE890:
        break
