import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
p=pathlib.Path("build_univ230/cmd_fix23.exe").read_bytes()
e=struct.unpack_from("<I",p,0x3C)[0]
ns=struct.unpack_from("<H",p,e+6)[0]; so=struct.unpack_from("<H",p,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if p[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",p,o+8); break
for pat,desc in ((bytes.fromhex("668b04c5"),"mov ax,[rax*8+d32]"),
                 (bytes.fromhex("8d047f"),"lea eax,[rdi+rdi*2]"),
                 (bytes.fromhex("488d047f"),"lea rax,[rdi+rdi*2]")):
    i=rp; found=[]
    while True:
        j=p.find(pat,i,rp+rs)
        if j<0: break
        found.append(va+j-rp); i=j+1
    print(desc, [hex(f) for f in found][:12])
