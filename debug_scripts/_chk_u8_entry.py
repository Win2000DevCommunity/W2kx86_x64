from pathlib import Path
from tools.audit_calls import read_text_section, load_map
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct
trva,data,_=read_text_section(Path("build_univ8/cmd_pure.exe").read_bytes())
rmap=load_map(Path("build_univ8/rva.txt"))
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("0xa4e7 map", hex(rmap.get(0xa4e7,0)))
# find mov rax,2464 near 0x49a00
pat=bytes.fromhex("48c7c064240000")
hits=[]
s=0
while True:
    i=data.find(pat,s)
    if i<0: break
    hits.append(trva+i); s=i+1
print("openings", [hex(h) for h in hits])
# calls to openings vs opening+7
for h in hits:
    n0=n1=0
    for i in range(len(data)-5):
        if data[i]!=0xe8: continue
        t=(trva+i+5+struct.unpack_from("<i",data,i+1)[0])&0xffffffff
        if t==h: n0+=1
        if t==h+7: n1+=1
    print(hex(h), "direct", n0, "plus7", n1)

# call at ~0x1187a target
for i in range(0x11800-trva, 0x11900-trva):
    if data[i]==0xe8 and bytes(data[i-4:i])==bytes.fromhex("4883e4f0"):
        t=(trva+i+5+struct.unpack_from("<i",data,i+1)[0])&0xffffffff
        if 0x49000 < t < 0x4a000:
            print("caller stub", hex(trva+i), "->", hex(t))
