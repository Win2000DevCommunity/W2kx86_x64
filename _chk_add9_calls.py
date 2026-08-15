from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3C)[0]
base=struct.unpack_from("<I",src,e+24+28)[0]
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
# find all call add9
add9=base+0xadd9
hits=[]
i=0
while i<len(blob)-5:
    if blob[i]==0xE8:
        rel=struct.unpack_from("<i",blob,i+1)[0]
        tgt=base+va32+i+5+rel
        if tgt==add9:
            hits.append(base+va32+i)
        i+=5
    else:
        i+=1
print("add9 call sites:", [hex(h) for h in hits])
for h in hits:
    fo=raw32+(h-base-va32)
    print(f"\n=== caller {h:#x} ===")
    # back up a bit for context
    start=max(0, fo-0x30)
    for insn in md.disasm(src[start:fo+5], base+va32+(start-raw32)):
        mark=" <<" if insn.address==h else ""
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}{mark}")
