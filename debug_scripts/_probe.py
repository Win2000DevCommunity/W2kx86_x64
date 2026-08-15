import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
exe=r"build_out19\cmd_pure.exe"
pe=pefile.PE(exe); data=bytes(pe.get_memory_mapped_image())
# find all mov rax,0x2464 (48 c7 c0 64 24 00 00)
pat=bytes.fromhex("48c7c064240000")
i=0; locs=[]
while True:
    j=data.find(pat,i)
    if j<0: break
    locs.append(j); i=j+1
print("mov rax,0x2464 at:", [hex(x) for x in locs])
# chkstk body: cmp eax,0x1000 then push rcx etc
for sig in (bytes.fromhex("3d00100000514889 4c2408".replace(" ","")), bytes.fromhex("513d00100000488d4c2408")):
    k=data.find(sig)
    print("chkstk sig", sig[:4].hex(), "at", hex(k) if k>=0 else None)
# what is at 0x13315
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("--- 0x13315 ---")
for ins in md.disasm(data[0x13315:0x13315+0x14],0x13315):
    print("  %06x %s %s"%(ins.address,ins.mnemonic,ins.op_str))
# reverse: which x86 rva maps to 0x13315 and 0x42584
m={}
for l in open(r"build_out19\rva.txt"):
    a,b=l.split(); m[int(a,16)]=int(b,16)
rev={}
for r,o in m.items(): rev.setdefault(o,[]).append(r)
for o in (0x13315,0x42584):
    print(hex(o),"<- x86", [hex(x) for x in sorted(rev.get(o,[]))][:6])
