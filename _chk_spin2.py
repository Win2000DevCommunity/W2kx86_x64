from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from tools.audit_calls import read_text_section, load_map
import struct

src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break
base=struct.unpack_from("<I",src,e+24+28)[0]
md32=Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 0x51e0-0x5280 ===")
for insn in md32.disasm(text[0x51e0-text_rva:0x5280-text_rva], base+0x51e0, count=50):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():16s} {insn.mnemonic} {insn.op_str}")

rmap=load_map(Path("build_univ12/rva.txt"))
print("\nmaps:")
for o in range(0x51e0, 0x5280):
    if o in rmap: print(f"  {o:#07x} -> {rmap[o]:#07x}")

# Also check univ11 for same site
rmap11=load_map(Path("build_univ11/rva.txt"))
trva,data,_=read_text_section(Path("build_univ11/cmd_pure.exe").read_bytes())
md64=Cs(CS_ARCH_X86, CS_MODE_64)
xr=rmap11.get(0x5220) or rmap11.get(0x5216)
print(f"\nuniv11 map 0x5216->{rmap11.get(0x5216)} around:")
if xr:
  for insn in md64.disasm(data[xr-0x20-trva:xr+0x40-trva], xr-0x20, count=25):
    print(f"  {insn.address:#07x}  {insn.bytes.hex():24s} {insn.mnemonic} {insn.op_str}")
