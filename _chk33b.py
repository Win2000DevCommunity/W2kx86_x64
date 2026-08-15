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
        break
rmap = {}
for ln in pathlib.Path("build_univ33/rva.txt").read_text().splitlines():
    a = ln.split()
    rmap[int(a[0], 16)] = int(a[1], 16)

# Find calls near x86 b75f
print("b75f map", hex(rmap.get(0xB75F, 0)))
md = Cs(CS_ARCH_X86, CS_MODE_64)
# scan all E8 that target 4aae8 or 4aad8
for tgt in (0x4AAE8, 0x4AAD8, 0x4AB25):
    count = 0
    for i in range(len(text) - 5):
        if text[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", text, i + 1)[0]
        dest = text_rva + i + 5 + rel
        if dest == tgt:
            count += 1
            if count <= 3:
                print(f"call at {hex(text_rva+i)} -> {hex(dest)}")
    print(f"total calls to {hex(tgt)}: {count}")

# Check what b75f call actually goes to
site = rmap.get(0xB75F)
if site:
    print("==== around b75f site", hex(site), "====")
    for insn in md.disasm(text[site - 20 - text_rva : site - text_rva + 40], site - 20):
        print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
