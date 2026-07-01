import sys, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
build=sys.argv[1] if len(sys.argv)>1 else "build_out30"
imm=int(sys.argv[2],16) if len(sys.argv)>2 else 0x2464
pe=pefile.PE(build+r"\cmd_pure.exe"); data=bytes(pe.get_memory_mapped_image())
md=Cs(CS_ARCH_X86,CS_MODE_64)
import struct
spill=bytes.fromhex('48894c2408'+'4889542410'+'4c89442418'+'4c894c2420'+'4c8d7c2404')
openers=[b'\x48\xc7\xc0'+struct.pack('<i',imm), b'\xb8'+struct.pack('<I',imm)]
for op in openers:
    start=0
    while True:
        p=data.find(op,start)
        if p<0: break
        start=p+1
        c=p+len(op)
        if data[c:c+len(spill)]==spill: c+=len(spill)
        tail=""
        if c<len(data) and data[c]==0xE8:
            rel=struct.unpack_from('<i',data,c+1)[0]; tgt=c+5+rel
            body=data[tgt:tgt+6]
            ischk = body[:5]==b'\x3d\x00\x10\x00\x00' or body[:6]==b'\x51\x3d\x00\x10\x00\x00'
            tail="call->0x%X %s"%(tgt, "CHKSTK" if ischk else "(not chkstk)")
        else:
            tail="no E8 after opener (next byte %02x)"%(data[c] if c<len(data) else 0)
        print("opener@0x%X %r  %s"%(p, op.hex(), tail))
