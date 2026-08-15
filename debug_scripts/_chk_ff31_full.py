from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct
pe=Path("build_univ97/cmd_pure.exe").read_bytes()
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
for line in Path("build_univ97/rva.txt").read_text().splitlines():
    a,b=line.replace("->"," ").split()[:2]
    rmap[int(a,16)]=int(b,16)
# disasm full ff31
md=Cs(CS_ARCH_X86,CS_MODE_64)
r=rmap[0xff31]
print("=== ff31 full ===")
for insn in md.disasm(pe[rp+(r-va):rp+(r-va)+0xb0], base+r):
    print(f"  {insn.address-base:#x}: {insn.bytes.hex():24} {insn.mnemonic} {insn.op_str}")
    if insn.address>=base+r+0xa0: break

# Compare: is c8d8 ever .rsrc-like in static? search mov to 698d8
print("\nstores targeting 698d8 / 6abc8:")
code=pe[rp:rp+rs]
for imm in (0x800698d8, 0x8006abc8, 0x80077000):
    pat=struct.pack("<Q",imm)
    idx=0; n=0
    while n<8:
        j=code.find(pat,idx)
        if j<0: break
        # sync disasm
        for back in range(0,16):
            insns=list(md.disasm(code[j-back:j+20], base+va+j-back, count=4))
            if insns and imm in (insns[0].address and 0 or 0) or any(hex(imm)[2:] in i.op_str for i in insns):
                print(f"  {imm:#x} near {va+j-back:#x}: " + "; ".join(f"{i.mnemonic} {i.op_str}" for i in insns[:3]))
                break
        idx=j+1; n+=1
