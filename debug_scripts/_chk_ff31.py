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

print("=== x86 0xff00..0xff80 (add9 caller) ===")
for insn in md.disasm(xt[0xfef0-xtr:0xfef0-xtr+0xa0], obase+0xfef0):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")

# Who sets c8d8 - search mov reg, imm 24320 then store
print("\n=== around GetCommandLine setup 0x5b00 pe64 / x86 0x40xx ===")
for insn in md.disasm(xt[0x3f80-xtr:0x3f80-xtr+0x100], obase+0x3f80):
    print(f"  {insn.address-obase:#07x}  {insn.mnemonic} {insn.op_str}")
    if insn.address-obase > 0x4050: break
