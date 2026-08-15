import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]; soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
for i in range(num):
    o = sec+i*40
    if src[o:o+5] == b".text":
        va, rs, rp = struct.unpack_from("<III", src, o+12)
        text = src[rp:rp+rs]; text_rva = va; break
base = struct.unpack_from("<I", src, e+24+28)[0]
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True

stores = []
for insn in md.disasm(text, base+text_rva):
    if not insn.operands:
        continue
    op0 = insn.operands[0]
    if op0.type != X86_OP_MEM:
        continue
    if (op0.mem.disp & 0xFFFFFFFF) != 0x4ad1c8d8:
        continue
    # destination mem with this disp
    if insn.mnemonic in ("mov", "and", "or", "xor", "add", "sub", "xchg", "lea"):
        stores.append((insn.address-base, insn.mnemonic, insn.op_str, op0.mem.base, op0.mem.index))

print("stores/ops with dest disp=c8d8:", len(stores))
for s in stores[:40]:
    print(f"  {s[0]:#07x}  base={s[3]} idx={s[4]}  {s[1]} {s[2]}")
