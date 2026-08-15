import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

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

md=Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
# Find E8 calls targeting 0x2485-0x2498
print("Calls into epilogue zone 0x2485-0x2498:")
for insn in md.disasm(text, base+text_rva):
    if insn.mnemonic!="call" or not insn.op_str.startswith("0x"):
        continue
    tgt=int(insn.op_str,16)-base
    if 0x2485 <= tgt <= 0x2498:
        print(f"  {insn.address-base:#07x} -> {tgt:#x}")

print("\n=== pe 0x2478..0x24b0 ===")
for insn in md.disasm(text[0x2478-text_rva:0x24b0-text_rva], base+0x2478, count=25):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():20}  {insn.mnemonic} {insn.op_str}")

# x86 callers of 0x27b2
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
md32=Cs(CS_ARCH_X86, CS_MODE_32); md32.detail=True
print("\nx86 calls to 0x27b2:")
rmap={}
for line in Path("build_univ20/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b
print("27b2 map", hex(rmap.get(0x27b2,0)))
for insn in md32.disasm(xt, obase+xtr):
    if insn.mnemonic!="call" or not insn.operands: continue
    if insn.operands[0].type!=1: continue  # IMM
    tgt=(insn.operands[0].imm-obase)&0xffffffff
    if tgt==0x27b2:
        xr=(insn.address-obase)&0xffffffff
        print(f"  x86 {xr:#x} -> 27b2; pe call site map {hex(rmap.get(xr,0))} tgt map {hex(rmap.get(0x27b2,0))}")
