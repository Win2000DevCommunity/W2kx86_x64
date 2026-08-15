import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

rmap={}
for line in Path("build_univ16/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b
print("b186->", hex(rmap.get(0xb186,0)), "b0d2->", hex(rmap.get(0xb0d2,0)), "b0c0->", hex(rmap.get(0xb0c0,0)))

data=Path("build_univ16/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
base=struct.unpack_from("<Q", data, e+24+24)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break

md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=rmap[0xb186]
print(f"\n=== body at b186 pe {pe:#x} ===")
off=pe-text_rva
for insn in md.disasm(text[off:off+80], base+pe, count=15):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")

print("\n=== call sites near b0d2 map ===")
pe2=rmap[0xb0d2]
off=pe2-text_rva
for insn in md.disasm(text[max(0,off-32):off+64], base+pe2-min(32,off), count=25):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")

# data ptr
ds=None
for i in range(num):
    o=sec+i*40
    name=data[o:o+8].split(b"\x00")[0].decode()
    vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
    if name==".data":
        print("c8d8", hex(struct.unpack_from("<Q", data, rp+0x8d8)[0]))
