import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src=open(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe","rb").read()
e=struct.unpack_from("<I",src,0x3c)[0]
n=struct.unpack_from("<H",src,e+6)[0]; opt=struct.unpack_from("<H",src,e+20)[0]; s0=e+24+opt
obase=struct.unpack_from("<I",src,e+24+28)[0]
# relocs
# data dirs
magic=struct.unpack_from('<H',src,e+24)[0]
# PE32
dd_off = e+24+96  # optional header data dirs for PE32
reloc_rva,reloc_sz=struct.unpack_from('<II',src,dd_off+5*8)
print("reloc",hex(reloc_rva),hex(reloc_sz))

# find section for reloc
for i in range(n):
    o=s0+i*40
    name=src[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8)
    if va <= reloc_rva < va+vs:
        reloc=src[rp+(reloc_rva-va):rp+(reloc_rva-va)+reloc_sz]
        break
    if name.startswith(b'.text'):
        xt=src[rp:rp+rs]; xtr=va

# collect HIGHLOW relocs in adad range
addrs=set()
p=0
while p+8<=len(reloc):
    page,size=struct.unpack_from('<II',reloc,p)
    if size<8: break
    for q in range(p+8,p+size,2):
        ent=struct.unpack_from('<H',reloc,q)[0]
        typ,off=ent>>12, ent&0xfff
        if typ==3: # HIGHLOW
            addrs.add(page+off)
    p+=size

for a in sorted(x for x in addrs if 0xadad <= a <= 0xadd6):
    # what dword is there
    off=a-xtr
    val=struct.unpack_from('<I',xt,off)[0]
    print(f"reloc at {a:#x} val {val:#x} (va {val:#x})")

print("\nx86 adad raw bytes:")
print(xt[0xadad-xtr:0xadd6-xtr].hex())

# expected remaps
old_data,new_data=0x1c000,0x69000
def remap(va):
    rva=va-obase
    if 0x1c000 <= rva < 0x1c000+0xd3cc:
        return 0x80000000+new_data+(rva-old_data)
    return None
for va in (0x4ad1fbe2,0x4ad21820,0x4ad22844,0x4ad1fbc8,0x4ad21000):
    print(f"expect {va:#x} -> {remap(va):#x}")
