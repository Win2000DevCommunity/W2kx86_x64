import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

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

# find mov [ebp-0x28] or similar with 0x4ad20c00
# x86 near b700 from earlier map
md = Cs(CS_ARCH_X86, CS_MODE_32)
needle = struct.pack("<I", 0x4AD20C00)
idx = 0
while True:
    j = blob.find(needle, idx)
    if j < 0:
        break
    addr = tva + j
    print(f"imm at {hex(addr)}")
    for back in range(0, 8):
        for insn in md.disasm(blob[j - back : j - back + 16], addr - back):
            if needle in bytes(insn.bytes) or "4ad20c00" in insn.op_str:
                print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                break
        else:
            continue
        break
    idx = j + 1

print("==== around b700 ====")
for insn in md.disasm(blob[0xB6E0 - tva : 0xB6E0 - tva + 120], 0xB6E0):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0xB750:
        break
