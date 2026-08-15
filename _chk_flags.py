import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

src=open(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe","rb").read()
e=struct.unpack_from("<I",src,0x3c)[0]
n=struct.unpack_from("<H",src,e+6)[0]; opt=struct.unpack_from("<H",src,e+20)[0]; s0=e+24+opt
obase=struct.unpack_from("<I",src,e+24+28)[0]
for i in range(n):
    o=s0+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8); xt=src[rp:rp+rs]; xtr=va; break
md=Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 add9 continued ae2a..af80 ===")
for insn in md.disasm(xt[0xae2a-xtr:0xae2a-xtr+0x200], obase+0xae2a):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
    if insn.address-obase >= 0xaf90: break

# Who calls add9 / adad with what flags?
print("\n=== call sites to add9 ===")
# E8 rel32 to add9
target=0xadd9
for i in range(len(xt)-5):
    if xt[i]==0xE8:
        rel=struct.unpack_from('<i',xt,i+1)[0]
        dest=(xtr+i+5+rel)&0xffffffff
        if dest==target:
            rva=xtr+i
            start=max(0,i-20)
            print(f"call at {rva:#x}:")
            for insn in md.disasm(xt[start:i+5], obase+xtr+start):
                print(f"  {insn.address-obase:#07x}  {insn.mnemonic} {insn.op_str}")
            print()
