import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from tools.audit_calls import read_text_section, load_map

src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break
base=struct.unpack_from("<I",src,e+24+28)[0]
md32=Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 longjmp gate 0xf000 ===")
for insn in md32.disasm(text[0xf000-text_rva:0xf040-text_rva], base+0xf000, count=25):
    print(f"{insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")

print("\n=== x86 helper 0xadd9 ===")
for insn in md32.disasm(text[0xadd9-text_rva:0xae50-text_rva], base+0xadd9, count=40):
    print(f"{insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")

rmap=load_map(Path("build_univ11/rva.txt"))
trva,data,_=read_text_section(Path("build_univ11/cmd_pure.exe").read_bytes())
md64=Cs(CS_ARCH_X86, CS_MODE_64)
for xa in [0xf00f, 0xf016, 0xf018, 0xf01a, 0xadd9, 0xade5, 0xadf0]:
    print(f"map {xa:#x} -> {rmap.get(xa)}")
print("\n=== x64 longjmp gate ===")
xr=rmap.get(0xf00f, 0)
for insn in md64.disasm(data[xr-trva:xr-trva+80], xr, count=25):
    print(f"{insn.address:#07x}  {insn.bytes.hex():24s} {insn.mnemonic} {insn.op_str}")
print("\n=== x64 helper 0x1397c area ===")
xr=rmap.get(0xadd9, 0)
print(f"entry {xr:#x}")
for insn in md64.disasm(data[xr-trva:xr-trva+120], xr, count=40):
    print(f"{insn.address:#07x}  {insn.bytes.hex():24s} {insn.mnemonic} {insn.op_str}")
