from pathlib import Path
import struct
data=Path("build_univ92/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",data,0x3C)[0]
nsec=struct.unpack_from("<H",data,e+6)[0]
osz=struct.unpack_from("<H",data,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    name=data[off:off+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",data,off+8)
    if name==b".text":
        text=data[raw:raw+rsz]; text_va=va
hits=[]
i=0
while i < len(text)-5:
    if 0xb8 <= text[i] <= 0xbf:
        imm=struct.unpack_from("<I", text, i+1)[0]
        if (imm & 0xffff) == 0xfbe2 or (0x4ad00000 <= imm < 0x4ad48000) or imm==0x8001fbe2:
            hits.append((text_va+i, imm))
    i+=1
print("hits", [(hex(a),hex(b)) for a,b in hits])
