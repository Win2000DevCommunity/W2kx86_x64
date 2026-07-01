import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
m={}
for l in open(r"build_out22\rva.txt"):
    a,b=l.split(); m[int(a,16)]=int(b,16)
pe=pefile.PE(r"build_out22\cmd_pure.exe"); data=pe.get_memory_mapped_image()
md=Cs(CS_ARCH_X86,CS_MODE_64)
for tag,off in (("0xa4e7 entry",m[0xa4e7]),("call-site 0x9f4c",m[0x9f4c])):
    print("---",tag,hex(off),"---")
    for i in md.disasm(bytes(data[off:off+0x14]), off):
        print("  %06x  %s %s"%(i.address,i.mnemonic,i.op_str))
