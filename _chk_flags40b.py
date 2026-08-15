from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct

rmap={}
rev={}
for line in Path("build_univ97/rva.txt").read_text().splitlines():
    a,b=line.replace("->"," ").split()[:2]
    oa,nb=int(a,16),int(b,16)
    rmap[oa]=nb
    rev.setdefault(nb,[]).append(oa)

# map return sites from previous crash
for rva in (0x1E6B0, 0x1C306, 0x1793B, 0x14AE8):
    # find nearest x86
    cands=sorted(((abs(nb-rva),oa,nb) for oa,nb in rmap.items()), key=lambda x:x[0])[:5]
    print(f"pe64 {rva:#x}:")
    for d,oa,nb in cands:
        print(f"  x86 {oa:#x} -> {nb:#x} d={d}")

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
    if name==b".rsrc": print("rsrc va",hex(va),"size",hex(vsz))

# find push 0x40 near calls that eventually hit add9
md=Cs(CS_ARCH_X86,CS_MODE_32)
blob=src[raw32:raw32+rsz32]
# search for 6A 40 (push 0x40)
idx=0
print("\npush 0x40 sites:")
while True:
    j=blob.find(b"\x6a\x40", idx)
    if j<0: break
    rva=va32+j
    # disasm window
    for insn in md.disasm(blob[j:j+0x30], base32+rva):
        print(f"  {insn.address-base32:#x}: {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic in ("call","ret","jmp") and insn.address>base32+rva+2:
            break
    print()
    idx=j+1
    if idx>200000: break
