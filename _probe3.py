import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
exe=r"build_out20\cmd_pure.exe"
pe=pefile.PE(exe); data=bytes(pe.get_memory_mapped_image())
ck=0x30FBC
# all mov rax,0x2464 and mov eax,0x2464
for tag,pat in (("mov rax",bytes.fromhex("48c7c064240000")),("mov eax",bytes.fromhex("b864240000"))):
    i=0
    while True:
        j=data.find(pat,i)
        if j<0: break
        c=j+len(pat)
        info=""
        if data[c]==0xe8:
            crel=int.from_bytes(data[c+1:c+5],"little",signed=True)
            t=c+5+crel
            info="call->%x %s"%(t,"==CK" if t==ck else "!=ck")
        else:
            info="next=%02x"%data[c]
        print("%s at %x  %s"%(tag,j,info))
        i=j+1
print("ck byte check @%x:"%ck, data[ck:ck+6].hex())
