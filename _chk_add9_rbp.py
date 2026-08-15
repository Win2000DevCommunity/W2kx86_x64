from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
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
# add9 body stores to rbp+0x10 / rsi origins
r=rmap[0xadd9]
print("add9 at", hex(r))
code=pe[rp+(r-va):rp+(r-va)+0x500]
for insn in md.disasm(code, base+r):
    if "rbp + 0x10" in insn.op_str or "rbp+0x10" in insn.op_str.replace(" ",""):
        print(f"  {insn.address-base:#x}: {insn.mnemonic} {insn.op_str}")
    if insn.address>=base+r+0x4c0: break

# x86 path that could load .rsrc into esi - search mov esi with rsrc or lea
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3C)[0]
base32=struct.unpack_from("<I",src,e+24+28)[0]
nsec=struct.unpack_from("<H",src,e+6)[0]
osz=struct.unpack_from("<H",src,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    name=src[off:off+8].split(b"\0",1)[0]
    vsz,va32,rsz,raw=struct.unpack_from("<IIII",src,off+8)
    if name==b".text": break
    if name==b".rsrc": rsrc=base32+va32; print("rsrc va", hex(rsrc))

# Who calls ff31 with 0x40? Check pe64 callers of ff31 for mov ecx, 0x40
ff=rmap[0xff31]
print("\ncalls to ff31:")
i=0
code=pe[rp:rp+rs]
while i < len(code)-5:
    if code[i]==0xe8:
        rel=struct.unpack_from("<i",code,i+1)[0]
        tgt=va+i+5+rel
        if tgt==ff:
            # disasm back
            start=max(0,i-0x30)
            print(f"\n call site @{va+i:#x}")
            for insn in md.disasm(code[start:i+5], base+va+start):
                print(f"  {insn.address-base:#x}: {insn.mnemonic} {insn.op_str}")
        i+=5
    else:
        i+=1
