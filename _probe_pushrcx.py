import struct, pathlib
from x86x64.translator._healing import HealingMixin

class T(HealingMixin):
    pass

t = T()
t._cmd_no_hacks = True
t._pure_cave_cursor = 0

pe = bytearray(pathlib.Path("build_univ256/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]
so = struct.unpack_from("<H", pe, e + 20)[0]
sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe[o:o + 5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8)
        break
blob = bytearray(pe[rp:rp + rs])
print("before 18110", blob[0x18110 - va:0x18110 - va + 16].hex())
n = t._pure_fix_push_reg_as_win64_arg0(blob)
print("fixed", n)
print("after 18110", blob[0x18110 - va:0x18110 - va + 16].hex())
# show jcc target
jcc_at = 0x18111 - va
rel = struct.unpack_from("<i", blob, jcc_at + 2)[0]
land = jcc_at + 6 + rel
print("je ->", hex(land + va), blob[land:land + 12].hex())
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(bytes(blob[land:land + 16]), 0x80000000 + land + va):
    print(f"  {insn.address-0x80000000:06X}: {insn.mnemonic} {insn.op_str}")

pe[rp:rp + rs] = blob
dst = pathlib.Path("build_univ256/cmd_probe_pushrcx.exe")
dst.write_bytes(pe)
print("wrote", dst)
