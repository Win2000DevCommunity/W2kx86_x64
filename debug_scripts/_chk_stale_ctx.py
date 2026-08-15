from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct

pe=Path("build_univ96/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
base=struct.unpack_from("<Q",pe,e+24+24)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    if pe[off:off+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8); break
code=pe[rp:rp+rs]
rva=0x565c0
off=rva-va
print("bytes around:", code[off-0x40:off+0x20].hex())
md=Cs(CS_ARCH_X86,CS_MODE_64)
# try several sync points
for sync in range(off-0x40, off+1):
    insns=list(md.disasm(code[sync:off+16], base+va+sync, count=12))
    hit=False
    for insn in insns:
        if insn.address-base <= rva < insn.address-base+len(insn.bytes):
            hit=True
            break
    if hit and any("8001fbe2" in i.op_str or "0x8001" in i.op_str for i in insns):
        print(f"\nsync@{va+sync:#x}:")
        for insn in insns:
            mark=" <<" if insn.address-base <= rva < insn.address-base+len(insn.bytes) else ""
            print(f"  {insn.address-base:#x}: {insn.bytes.hex():24} {insn.mnemonic} {insn.op_str}{mark}")
        break
else:
    # just dump from aligned start looking for c7 / b8 with that imm
    print("searching nearby mov imm...")
    for i in range(max(0,off-0x80), off+0x10):
        # C7 /0 id  or B8+rd
        if code[i]==0xC7 and i+6<=len(code):
            # need modrm
            pass
        if code[i] in range(0xb8,0xc0) and struct.unpack_from("<I",code,i+1)[0]==0x8001fbe2:
            print(f"mov reg @{va+i:#x}")
        if i+6<len(code) and struct.unpack_from("<I",code,i)[0]==0x8001fbe2:
            print(f"imm at {va+i:#x}, prev bytes {code[i-8:i].hex()}")
