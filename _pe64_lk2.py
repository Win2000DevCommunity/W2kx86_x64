import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ230/cmd_fix21.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
for insn in md.disasm(pe[rp+(0x18fa8-va):rp+(0x190f0-va)], 0x80000000+0x18fa8):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
