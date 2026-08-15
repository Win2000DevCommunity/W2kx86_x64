import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

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
print("=== PE64 @ 0x369a0 (mapped near b180) ===")
off=0x369a0-text_rva
for insn in md.disasm(text[off:off+0x80], base+0x369a0, count=30):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}")

# Find pattern: movabs r11, 0x8005fbc8; mov r??, qword ptr [r11]; cmp word
needle=bytes.fromhex("49bb") + struct.pack("<Q", 0x8005fbc8)
i=0
found=0
while found<30:
    j=text.find(needle,i)
    if j<0: break
    rva=text_rva+j
    # disasm a window and check if next is load from r11 then cmp word
    window=text[j:j+40]
    insns=list(md.disasm(window, base+rva, count=6))
    syn=" | ".join(f"{x.mnemonic} {x.op_str}" for x in insns)
    if "qword ptr [r11]" in syn and ("word ptr" in syn or "cmp" in syn):
        print(f"\nCANDIDATE {rva:#x}: {syn}")
    i=j+1
    found+=1

# Check univ14 for same call site health
print("\n=== compare univ14 call site ===")
p=Path("build_univ14/cmd_pure.exe")
if p.exists():
    d=p.read_bytes()
    e=struct.unpack_from("<I", d, 0x3c)[0]
    soh=struct.unpack_from("<H", d, e+20)[0]; sec=e+24+soh
    num=struct.unpack_from("<H", d, e+6)[0]
    base=struct.unpack_from("<Q", d, e+24+24)[0]
    for i in range(num):
        o=sec+i*40
        if d[o:o+5]==b".text":
            vs,va,rs,rp=struct.unpack_from("<IIII", d, o+8)
            t=d[rp:rp+rs]; tr=va; break
    # find similar pattern cmp ax,0xa; mov [rdi],ax near calls
    # use rva map from univ14 if present
    rm=Path("build_univ14/rva.txt")
    if rm.exists():
        rmap={}
        for line in rm.read_text().splitlines():
            a,b=[int(x,16) for x in line.split()[:2]]
            rmap[a]=b
        print("univ14 b186->", hex(rmap.get(0xb186,0)), "b0d2->", hex(rmap.get(0xb0d2,0)), "b0c0->", hex(rmap.get(0xb0c0,0)))
        pe=rmap.get(0xb0d2)
        if pe:
            off=pe-tr
            for insn in md.disasm(t[off-16:off+48], base+pe-16, count=20):
                print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
