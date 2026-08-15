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
    name=pe[off:off+8].split(b"\0",1)[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8)
    if name==b".text": text=pe[rp:rp+rs]; tva=va
    if name==b".rsrc": print("rsrc", hex(va), "va", hex(base+va))
rsrc_va=base+0x78000
print("count qword", pe.count(struct.pack("<Q", rsrc_va)), "dword", pe.count(struct.pack("<I", rsrc_va & 0xffffffff)))
# also old rsrc
print("old rsrc 4ad2a000 dword", pe.count(struct.pack("<I", 0x4ad2a000)))
md=Cs(CS_ARCH_X86,CS_MODE_64)
# find movabs with rsrc
pat=bytes([0x48,0xbb])+struct.pack("<Q",rsrc_va)  # movabs rbx
# any rex + b8-bf
idx=0; hits=0
while hits<30 and idx < len(text)-10:
    if text[idx] in (0x48,0x49,0x4c,0x4d) and 0xb8 <= text[idx+1] <= 0xbf:
        imm=struct.unpack_from("<Q",text,idx+2)[0]
        if imm == rsrc_va or (0x4ad2a000 <= (imm & 0xffffffff) < 0x4ad48000):
            print(f"  movabs @{tva+idx:#x} imm={imm:#x}")
            hits+=1
        idx+=10
    else:
        idx+=1
# C7 with rsrc imm
pat=struct.pack("<I", rsrc_va & 0xffffffff)
idx=0; hits=0
while hits<20:
    j=text.find(pat,idx)
    if j<0: break
    # context
    for b in range(1,8):
        if j>=b and text[j-b]==0xc7:
            print(f"  c7 imm @{tva+j-b:#x} {text[j-b:j+4].hex()}")
            hits+=1
            break
    idx=j+1
