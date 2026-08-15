import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
m32=Cs(CS_ARCH_X86, CS_MODE_32); m64=Cs(CS_ARCH_X86, CS_MODE_64)
x=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",x,0x3C)[0]; ib=struct.unpack_from("<I",x,e+0x34)[0]
ns=struct.unpack_from("<H",x,e+6)[0]; so=struct.unpack_from("<H",x,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if x[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",x,o+8); break
print("==== x86 d05c..d1f8 ====")
for insn in m32.disasm(x[rp+(0xd05c-va):rp+(0xd1f8-va)], ib+0xd05c):
    print(f"  {insn.address&0xffffff:#07x}: {insn.mnemonic} {insn.op_str}")
