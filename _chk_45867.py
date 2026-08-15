from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib, sys, ctypes as C, os
from ctypes import wintypes
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ228/full.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
code = bytes(pe[rp:rp+rs])
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("==== after 45862 call (45867+) ====")
for i, insn in enumerate(md.disasm(code[0x45867-va:0x45920-va], ib+0x45867)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i > 40: break

print("==== 17c31 area ====")
for i, insn in enumerate(md.disasm(code[0x17c00-va:0x17c80-va], ib+0x17c00)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i > 30: break
