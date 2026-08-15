import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
md=Cs(CS_ARCH_X86, CS_MODE_32)
x86=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",x86,0x3C)[0]
ib=struct.unpack_from("<I",x86,e+0x34)[0]
ns=struct.unpack_from("<H",x86,e+6)[0]; so=struct.unpack_from("<H",x86,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if x86[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",x86,o+8); break
off=rp+(0xcdc6-va)
for insn in md.disasm(x86[off:off+0x120], ib+0xcdc6):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
