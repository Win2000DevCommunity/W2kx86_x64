import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

base = pathlib.Path("build_univ31")
raw = (base / "cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", raw, 0x3C)[0]
n = struct.unpack_from("<H", raw, e + 6)[0]
opt = struct.unpack_from("<H", raw, e + 20)[0]
s0 = e + 24 + opt
secs = []
for i in range(n):
    o = s0 + i * 40
    name = raw[o : o + 8].split(b"\x00")[0]
    vsz, va, rsz, rp = struct.unpack_from("<IIII", raw, o + 8)
    secs.append((name, va, vsz, rp, rsz))
    if name.startswith(b".text"):
        text = raw[rp : rp + rsz]
        text_rva = va
    if b"data" in name.lower():
        data = raw[rp : rp + rsz]
        data_rva = va
        print("data", hex(va), "off 1c0", data[0x1C0:0x1E0].hex())
        try:
            print(" as utf16", data[0x1C0:0x1E0].decode("utf-16-le"))
        except Exception as ex:
            print(ex)

rmap = {}
rev = {}
for ln in (base / "rva.txt").read_text().splitlines():
    a = ln.split()
    x, y = int(a[0], 16), int(a[1], 16)
    rmap[x] = y
    rev[y] = x

md = Cs(CS_ARCH_X86, CS_MODE_64)
# code near RSI 0x14E49
print("==== near 14E49 ====")
for insn in md.disasm(text[0x14E20 - text_rva : 0x14E60 - text_rva], 0x14E20):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")

# find what x86 maps near 14E49
best = None
for y, x in rev.items():
    if y <= 0x14E49 and (best is None or y > best[0]):
        best = (y, x)
print("nearest map", hex(best[0]), "x86", hex(best[1]))

# original around that
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
x86 = best[1]
print("==== x86", hex(x86), "====")
for insn in md32.disasm(blob[x86 - 30 - tva : x86 - tva + 40], x86 - 30):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
