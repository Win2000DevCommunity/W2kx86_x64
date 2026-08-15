import sys, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
build=sys.argv[1] if len(sys.argv)>1 else "build_out30"
rva=int(sys.argv[2],16)
length=int(sys.argv[3],16) if len(sys.argv)>3 else 0x80
m={}
for l in open(build+r"\rva.txt"):
    a,b=l.split(); m[int(a,16)]=int(b,16)
pe=pefile.PE(build+r"\cmd_pure.exe"); data=pe.get_memory_mapped_image()
md=Cs(CS_ARCH_X86,CS_MODE_64)
if rva in m:
    off=m[rva]; print("x86 0x%X -> translated 0x%X"%(rva,off))
else:
    keys=sorted(k for k in m if k<=rva); off=m[keys[-1]]+(rva-keys[-1])
    print("x86 0x%X ~ x86 0x%X -> 0x%X (+%d)"%(rva,keys[-1],off,rva-keys[-1]))
for i in md.disasm(bytes(data[off:off+length]), off):
    print("  %06x  %s %s"%(i.address,i.mnemonic,i.op_str))
