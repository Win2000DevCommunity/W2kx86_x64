from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct

src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3C)[0]
base32=struct.unpack_from("<I",src,e+24+28)[0]
nsec=struct.unpack_from("<H",src,e+6)[0]
osz=struct.unpack_from("<H",src,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    name=src[off:off+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",src,off+8)
    if name==b".text": va32,raw32,rsz32=va,raw,rsz

blob=src[raw32:raw32+rsz32]
md=Cs(CS_ARCH_X86,CS_MODE_32)
ff31=base32+0xff31
print("callers of ff31:")
i=0
while i<len(blob)-5:
    if blob[i]==0xE8:
        rel=struct.unpack_from("<i",blob,i+1)[0]
        tgt=base32+va32+i+5+rel
        if tgt==ff31:
            rva=va32+i
            print(f"\n=== call @{rva:#x} ===")
            start=max(0,i-0x20)
            for insn in md.disasm(blob[start:i+5], base32+va32+start):
                mark=" <<" if insn.address==base32+rva else ""
                print(f"  {insn.address-base32:#x}: {insn.mnemonic} {insn.op_str}{mark}")
        i+=5
    else:
        i+=1

# pe64 ff31 / add9 call marshalling
rmap={}
for line in Path("build_univ97/rva.txt").read_text().splitlines():
    a,b=line.replace("->"," ").split()[:2]
    rmap[int(a,16)]=int(b,16)
print("\nff31->",hex(rmap.get(0xff31,-1)), "ff43->",hex(rmap.get(0xff43,-1)), "ff49->",hex(rmap.get(0xff49,-1)))

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
md64=Cs(CS_ARCH_X86,CS_MODE_64)
r=rmap[0xff31]
off=r-va
print(f"\n=== pe64 ff31 @{r:#x} ===")
for insn in md64.disasm(pe[rp+off:rp+off+0x80], base+r):
    print(f"  {insn.address-base:#x}: {insn.mnemonic} {insn.op_str}")
    if insn.address>=base+r+0x70: break

# also caller that might pass 0x40 - search back from c71e area
print("\n=== x86 around c700 (prompt loop?) ===")
fo=raw32+(0xc6e0-va32)
for insn in md.disasm(src[fo:fo+0xa0], base32+0xc6e0):
    print(f"  {insn.address-base32:#x}: {insn.mnemonic} {insn.op_str}")
    if insn.address>=base32+0xc760: break
