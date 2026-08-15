import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src=open(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe","rb").read()
e=struct.unpack_from("<I",src,0x3c)[0]
n=struct.unpack_from("<H",src,e+6)[0]; opt=struct.unpack_from("<H",src,e+20)[0]; s0=e+24+opt
obase=struct.unpack_from("<I",src,e+24+28)[0]
for i in range(n):
    o=s0+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8); xt=src[rp:rp+rs]; xtr=va; break
md=Cs(CS_ARCH_X86, CS_MODE_32)
print("=== refill full to 0xb400 ===")
for insn in md.disasm(xt[0xb21c-xtr:0xb21c-xtr+0x200], obase+0xb21c):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
    if insn.address-obase >= 0xb3c0: break
