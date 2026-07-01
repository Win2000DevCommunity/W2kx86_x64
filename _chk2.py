import sys, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
m={}
for l in open(r"build_out18\rva.txt"):
    a,b=l.split(); m[int(a,16)]=int(b,16)
pe=pefile.PE(r"build_out18\cmd_pure.exe"); data=pe.get_memory_mapped_image()
md=Cs(CS_ARCH_X86,CS_MODE_64)
off=m[0x9f4c]
print("9f4c ->", hex(off))
for i in md.disasm(bytes(data[off:off+0x18]), off):
    tgt=""
    if i.mnemonic=="call" and i.op_str.startswith("0x"):
        tgt=" => "+i.op_str
    print("  %06x  %s %s%s"%(i.address,i.mnemonic,i.op_str,tgt))
