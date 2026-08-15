import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
m32=Cs(CS_ARCH_X86, CS_MODE_32); m64=Cs(CS_ARCH_X86, CS_MODE_64)
x86=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",x86,0x3C)[0]; ib=struct.unpack_from("<I",x86,e+0x34)[0]
ns=struct.unpack_from("<H",x86,e+6)[0]; so=struct.unpack_from("<H",x86,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if x86[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",x86,o+8); break
print("==== x86 cfd2 ====")
for insn in m32.disasm(x86[rp+(0xcfd2-va):rp+(0xcfd2-va)+0xa0], ib+0xcfd2):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

pe=pathlib.Path("build_univ230/cmd_fix20.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
print("==== pe64 18e98 ====")
for insn in m64.disasm(pe[rp+(0x18e98-va):rp+(0x18e98-va)+0x140], 0x80000000+0x18e98):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
