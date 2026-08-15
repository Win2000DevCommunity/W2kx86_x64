from pathlib import Path
import struct
pe=Path("build_univ98/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
base=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(nsec):
    off=soff+i*40
    name=pe[off:off+8].split(b"\0",1)[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8)
    if name==b".text": text=pe[rp:rp+rs]; tva=va
    if name==b".data":
        # find More?
        data=pe[rp:rp+rs]
        # string might be in .rdata part of data or rsrc
# search entire pe for utf16 More?
more= "More?".encode("utf-16-le")
idx=0
while True:
    j=pe.find(more,idx)
    if j<0: break
    print(f"utf16 More? at file@{j:#x}")
    idx=j+1
more8=b"More?"
idx=0
while True:
    j=pe.find(more8,idx)
    if j<0: break
    print(f"ascii More? at file@{j:#x}")
    idx=j+1

# refs to 0x80059668
pat=struct.pack("<Q", 0x80059668)
print("qword refs", text.count(pat))
idx=0
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86,CS_MODE_64)
while True:
    j=text.find(pat,idx)
    if j<0: break
    print(f"  @{tva+j:#x}")
    idx=j+1
