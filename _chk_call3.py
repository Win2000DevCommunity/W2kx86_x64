import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

data = Path("build_univ15/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", data, 0x3c)[0]
soh = struct.unpack_from("<H", data, e+20)[0]; sec = e+24+soh
num = struct.unpack_from("<H", data, e+6)[0]
base = struct.unpack_from("<Q", data, e+24+24)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break

md=Cs(CS_ARCH_X86, CS_MODE_64)
print("=== PE64 0x13f20..0x13f90 ===")
off=0x13f20-text_rva
for insn in md.disasm(text[off:off+0x80], base+0x13f20, count=40):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}")

# What is at b186 in x86?
src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
num = struct.unpack_from("<H", src, e+6)[0]
obase = struct.unpack_from("<I", src, e+24+28)[0]
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", src, o+8)
        xt=src[rp:rp+rs]; xtr=va; break
md32=Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 0xb186 function ===")
for insn in md32.disasm(xt[0xb186-xtr:0xb186-xtr+80], obase+0xb186, count=25):
    print(f"  {insn.address-obase:#07x}  {insn.mnemonic} {insn.op_str}")

# Where did pe 0x1482f come from - which repair?
# Search align-call repairs targeting nearby
print("\n=== bytes at supposed real target b186 pe map ===")
rmap={}
for line in Path("build_univ15/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b
print("b186->", hex(rmap.get(0xb186,0)))
print("b0d2->", hex(rmap.get(0xb0d2,0)))
print("b0c0->", hex(rmap.get(0xb0c0,0)))
# Find all pe addrs for b186 range
for a in range(0xb186, 0xb1c0):
    if a in rmap:
        print(f"  x86 {a:#x} -> pe {rmap[a]:#x}")
