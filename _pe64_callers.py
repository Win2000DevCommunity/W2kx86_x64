import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ230/cmd_fix20.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
def callers(t):
    res=[]
    for i in range(rp, rp+rs-5):
        if pe[i]==0xE8:
            rel=struct.unpack_from("<i",pe,i+1)[0]
            if va+(i-rp)+5+rel==t: res.append(va+(i-rp))
    return res
for t in (0xc514, 0x189c4):
    print(f"callers of {t:#x}:", [hex(c) for c in callers(t)])
