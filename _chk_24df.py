from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct

rmap={}
for line in Path("build_univ20/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b
print("24df->", hex(rmap.get(0x24df,0)))
print("2491->", hex(rmap.get(0x2491,0)))
for a in range(0x24d0, 0x2500):
    if a in rmap:
        print(f"  {a:#x}->{rmap[a]:#x}")

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
print("\n=== x86 0x24d0..0x2520 ===")
for insn in md.disasm(xt[0x24d0-xtr:0x2520-xtr], obase+0x24d0, count=25):
    print(f"  {insn.address-obase:#07x}  {insn.mnemonic} {insn.op_str}")

data=Path("build_univ20/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
base=struct.unpack_from("<Q", data, e+24+24)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break
md64=Cs(CS_ARCH_X86, CS_MODE_64)
pe=rmap.get(0x24df)
if pe:
    print(f"\n=== pe body at 24df map {pe:#x} ===")
    off=pe-text_rva
    for insn in md64.disasm(text[off:off+48], base+pe, count=15):
        print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
