from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from tools.audit_calls import read_text_section, load_map
import struct

rmap=load_map(Path("build_univ12/rva.txt"))
# reverse map
rev={}
for x86,x64 in rmap.items():
    rev.setdefault(x64, []).append(x86)

trva,data,_=read_text_section(Path("build_univ12/cmd_pure.exe").read_bytes())
md64=Cs(CS_ARCH_X86, CS_MODE_64)
print("=== x64 around 0x7707 ===")
for insn in md64.disasm(data[0x76e0-trva:0x7740-trva], 0x76e0, count=30):
    print(f"  {insn.address:#07x}  {insn.bytes.hex():24s} {insn.mnemonic} {insn.op_str}")

print("\nx86 RVAs mapping to 0x7707:", [hex(x) for x in rev.get(0x7707, [])])
for off in range(0x76e0, 0x7740):
    if off in rev:
        print(f"  x64 {off:#x} <- x86 {[hex(x) for x in rev[off]]}")

# x86 source
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break
base=struct.unpack_from("<I",src,e+24+28)[0]
md32=Cs(CS_ARCH_X86, CS_MODE_32)
x86s=rev.get(0x7707, [])
if x86s:
    xa=min(x86s)
    print(f"\n=== x86 around {xa:#x} ===")
    for insn in md32.disasm(text[xa-0x20-text_rva:xa+0x40-text_rva], base+xa-0x20, count=30):
        print(f"  {insn.address-base:#07x}  {insn.bytes.hex():16s} {insn.mnemonic} {insn.op_str}")
