from pathlib import Path
import struct
pe=Path("build_univ98/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    name=pe[off:off+8].split(b"\0",1)[0].decode()
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8)
    blob=pe[rp:rp+rs]
    for v,lab in [(0x80078000,"rsrc_new"),(0x4ad2a000,"rsrc_old"),(0x80000000,"base"),(0x78000,"rsrc_rva")]:
        cq=blob.count(struct.pack("<Q",v)) if v>0xffffffff else 0
        cd=blob.count(struct.pack("<I",v & 0xffffffff))
        if cq or cd:
            print(f"{name}: {lab} q={cq} d={cd}")
            # first few offsets
            pat=struct.pack("<I", v & 0xffffffff)
            idx=0; n=0
            while n<5:
                j=blob.find(pat,idx)
                if j<0: break
                print(f"  file_rva={va+j:#x}")
                idx=j+1; n+=1
