from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct
pe=Path("build_univ98/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
base=struct.unpack_from("<Q",pe,e+24+24)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    if pe[off:off+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8); break
rmap={}
for line in Path("build_univ98/rva.txt").read_text().splitlines():
    a,b=line.replace("->"," ").split()[:2]
    rmap[int(a,16)]=int(b,16)
md=Cs(CS_ARCH_X86,CS_MODE_64)
r=rmap[0xff31]
print("=== ff31 ===")
for insn in md.disasm(pe[rp+(r-va):rp+(r-va)+0x60], base+r):
    print(f"  {insn.address-base:#x}: {insn.mnemonic} {insn.op_str}")
    if insn.address>=base+r+0x50: break
print("lin_fbe2", pe.count(struct.pack("<I",0x8001fbe2)))
