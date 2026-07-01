import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
exe=r"build_out19\cmd_pure.exe"
pe=pefile.PE(exe); data=bytes(pe.get_memory_mapped_image())
sigs=(bytes.fromhex("3d000100000051488d4c2408"[:0]) ,)
real_sigs=(b"\x3d\x00\x10\x00\x00\x51\x48\x8d\x4c\x24\x08",
           b"\x51\x3d\x00\x10\x00\x00\x48\x8d\x4c\x24\x08")
for s in real_sigs:
    k=data.find(s); print("chkstk sig",s[:6].hex(),"->",hex(k) if k>=0 else None)
# also just cmp eax,0x1000
for s in (b"\x3d\x00\x10\x00\x00", b"\x51\x3d\x00\x10\x00\x00"):
    k=data.find(s); print("cmp eax,0x1000 variant",s.hex(),"->",hex(k) if k>=0 else None)
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("--- 0x125f1 entry+call ---")
for ins in md.disasm(data[0x125f1:0x125f1+0x18],0x125f1):
    print("  %06x %s %s"%(ins.address,ins.mnemonic,ins.op_str))
