import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

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

# Find sequence: load from 80063874, then cmp-like with 3a4, xor al,al / mov al,1
# Real e846 ends with xor al,al; ret / mov al,1; ret
needle = struct.pack("<Q", 0x80063874)
md = Cs(CS_ARCH_X86, CS_MODE_64)
idx = 0
while True:
    j = text.find(needle, idx)
    if j < 0:
        break
    addr = text_rva + j
    # show surrounding 30 bytes before (for movabs) through after
    start = max(0, j - 2)
    print(f"\n=== hit {hex(addr)} ===")
    for insn in md.disasm(text[start : j + 40], text_rva + start):
        print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
        if insn.address > addr + 30:
            break
    idx = j + 1

# Also search for xor al,al; ret pattern after loading that global - 
# look for B0 00 C3 near cmp 3a4
print("\n=== look for cmp eax,0x3a4 style near loads ===")
