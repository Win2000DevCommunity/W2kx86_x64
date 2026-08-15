import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

rmap={}
for line in Path("build_univ20/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b
# reverse pe->x86 for 1e4b and 2166
rev={}
for a,b in rmap.items():
    rev.setdefault(b,[]).append(a)
print("x86 for pe 1e4b:", [hex(x) for x in rev.get(0x1e4b, [])])
print("x86 for pe 2166:", [hex(x) for x in rev.get(0x2166, [])])
# nearby
for pe in range(0x1e40, 0x1e60):
    if pe in rev: print(f"  pe {pe:#x} <- {[hex(x) for x in rev[pe][:4]]}")
for pe in range(0x2158, 0x2178):
    if pe in rev: print(f"  pe {pe:#x} <- {[hex(x) for x in rev[pe][:4]]}")

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

# disasm pe site to see jcc
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
for site in (0x1e40, 0x2158):
    print(f"\n=== pe {site:#x} ===")
    off=site-text_rva
    for insn in md64.disasm(text[off:off+40], base+site, count=10):
        print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
