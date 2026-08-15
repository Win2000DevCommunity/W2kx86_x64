import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I", src, 0x3c)[0]
soh=struct.unpack_from("<H", src, e+20)[0]; sec=e+24+soh
obase=struct.unpack_from("<I", src, e+24+28)[0]
num=struct.unpack_from("<H", src, e+6)[0]
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", src, o+8)
        xt=src[rp:rp+rs]; xtr=va; break
md=Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 0x2220..0x2280 ===")
for insn in md.disasm(xt[0x2220-xtr:0x2280-xtr], obase+0x2220, count=30):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():20}  {insn.mnemonic} {insn.op_str}")
print("\n=== x86 0x2370..0x23c0 ===")
for insn in md.disasm(xt[0x2370-xtr:0x23c0-xtr], obase+0x2370, count=30):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():20}  {insn.mnemonic} {insn.op_str}")
