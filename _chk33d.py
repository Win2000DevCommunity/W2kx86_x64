import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

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

# find cmp word [rcx],0 near 14dd1
pat = bytes.fromhex("66833900")
for j in range(0x14D00 - text_rva, 0x14E80 - text_rva):
    if text[j:j+4] == pat:
        print("found at", hex(text_rva + j))

md = Cs(CS_ARCH_X86, CS_MODE_64)
# disassemble from 14d80 carefully
print("==== from 14d80 ====")
for insn in md.disasm(text[0x14D80 - text_rva : 0x14E20 - text_rva], 0x14D80):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")

# old VA occurrences in text
needle = struct.pack("<I", 0x4AD20C00)
idx = 0
md2 = Cs(CS_ARCH_X86, CS_MODE_64)
while True:
    j = text.find(needle, idx)
    if j < 0:
        break
    addr = text_rva + j
    print(f"\nold VA at {hex(addr)}, context:")
    for insn in md2.disasm(text[max(0,j-8):j+12], addr - min(8,j)):
        print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
    idx = j + 1
    if idx > 5:
        break
