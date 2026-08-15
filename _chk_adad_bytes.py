# Compare x86 adad bytes vs what remaps should be, and check pe64 for 22844
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

src=open(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe","rb").read()
e=struct.unpack_from("<I",src,0x3c)[0]
n=struct.unpack_from("<H",src,e+6)[0]; opt=struct.unpack_from("<H",src,e+20)[0]; s0=e+24+opt
for i in range(n):
    o=s0+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8); xt=src[rp:rp+rs]; xtr=va; break

raw=xt[0xadad-xtr:0xadd6-xtr]
print("x86 bytes", raw.hex())
# decode each abs
# 8b 44 24 04 = mov eax,[esp+4]
# 66 83 25 e2 fb d1 4a 00 = and word [0x4ad1fbe2],0
# a3 20 18 d2 4a = mov [0x4ad21820],eax
# 8b 44 24 08 = mov eax,[esp+8]
# a3 44 28 d2 4a = mov [0x4ad22844],eax
# b8 e2 fb d1 4a = mov eax,0x4ad1fbe2
# a3 c8 fb d1 4a = mov [0x4ad1fbc8],eax
# a3 00 10 d2 4a = mov [0x4ad21000],eax
# c2 08 00 = ret 8

pe=open(r"C:\Users\win2000\Desktop\univ88\cmd_pure.exe","rb").read()
# search for 0x8006f844 (22844 remap)
pat=struct.pack('<Q', 0x8006f844)
print("refs to 6f844 (22844):", pe.count(pat))
pat2=struct.pack('<Q', 0x8006cbe2)
print("refs to 6cbe2 (fbe2):", pe.count(pat2))
# in adad region only the and should use cbe2 - does movabs for cbe2 appear as and target?
# pe64 adad uses e820 for and - confirmed bug

# Check if 22844 store became 6e000 - maybe A3 translation uses wrong reloc
# Look at encoding of a3 in translator
