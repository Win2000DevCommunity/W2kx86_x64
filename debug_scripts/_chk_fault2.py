import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
src=r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
pe32=open(src,"rb").read()
e=struct.unpack_from("<I",pe32,0x3c)[0]
n=struct.unpack_from("<H",pe32,e+6)[0]
opt=struct.unpack_from("<H",pe32,e+20)[0]
s0=e+24+opt
for i in range(n):
 o=s0+i*40; name=pe32[o:o+8].split(b"\x00")[0]; vsz,va,rsz,raw=struct.unpack_from("<IIII",pe32,o+8)
 if name.startswith(b".text"): break
blob=pe32[raw:raw+rsz]
md=Cs(CS_ARCH_X86, CS_MODE_32)
print("==== 2200 ====")
for insn in md.disasm(blob[0x2200-va:0x2200-va+120], 0x2200):
 print(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
 if insn.address>0x2280: break
