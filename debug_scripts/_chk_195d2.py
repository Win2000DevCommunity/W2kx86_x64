import struct
from pathlib import Path
from tools.audit_calls import read_text_section, load_map
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from x86x64.translator._analysis import AnalysisMixin

trva,data,_=read_text_section(Path("build_univ3/cmd_pure.exe").read_bytes())
rmap=load_map(Path("build_univ3/rva.txt"))
md=Cs(CS_ARCH_X86, CS_MODE_64)

# Find real entry for 0x195d2 pattern near 0x2fdc4
print("scan back/forward from 0x2fdc4 for prologue_ok:")
for d in range(-32, 64):
    a=0x2fdc4+d
    if AnalysisMixin._x64_entry_prologue_ok(data, a-trva) and data[a-trva] not in (0xc3,0xc2):
        print(hex(a), data[a-trva:a-trva+8].hex())

# Who maps near 0x2fdcc?
near=[(o,n) for o,n in rmap.items() if abs(n-0x2fdcc)<40]
print("map near 0x2fdcc:", [(hex(o),hex(n)) for o,n in sorted(near,key=lambda x:x[1])])

# Find all cmp rcx,0 ; jne stubs (IAT null-check wrappers)
pat=b"\x48\x83\xf9\x00"
hits=[]
start=0
while True:
    i=data.find(pat,start)
    if i<0: break
    hits.append(trva+i)
    start=i+1
print("cmp rcx,0 count", len(hits), "first", [hex(h) for h in hits[:15]])

# For each call to 0x31e85, what's immediately before (align stub?)
c_sites=[]
for i in range(len(data)-5):
    if data[i]!=0xe8: continue
    t=(trva+i+5+struct.unpack_from("<i",data,i+1)[0])&0xffffffff
    if t==0x31e85:
        c_sites.append(trva+i)
print("sample call sites to 0x31e85:")
for s in c_sites[:5]:
    print(hex(s), "prev8", data[s-trva-8:s-trva].hex())
