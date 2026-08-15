from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct

pe=bytearray(Path("build_univ96/cmd_pure.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
base=struct.unpack_from("<Q",pe,e+24+24)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
sects=[]
for i in range(nsec):
    off=soff+i*40
    name=pe[off:off+8].split(b"\0",1)[0].decode()
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8)
    sects.append((name,va,vs,rs,rp))
    print(name, hex(va), hex(va+vs))

needle=struct.pack("<I",0x8001fbe2)
idx=0
md=Cs(CS_ARCH_X86,CS_MODE_64)
while True:
    j=pe.find(needle,idx)
    if j<0: break
    # which section?
    sec="?"
    rva=None
    for name,va,vs,rs,rp in sects:
        if rp<=j<rp+rs:
            rva=va+(j-rp)
            sec=name
            break
    print(f"\nhit file@{j:#x} sec={sec} rva={rva and hex(rva)} va={rva and hex(base+rva)}")
    if sec==".text" and rva is not None:
        # disasm around
        for name,va,vs,rs,rp in sects:
            if name==".text":
                code=bytes(pe[rp:rp+rs]); break
        start=max(0,rva-va-0x20)
        for insn in md.disasm(code[start:start+0x50], base+va+start):
            mark=" <<" if j==rp+(insn.address-base-va) or (insn.address-base<=rva<insn.address-base+len(insn.bytes)) else ""
            if abs((insn.address-base)-rva)<0x28:
                print(f"  {insn.address-base:#x}: {insn.mnemonic} {insn.op_str}{mark}")
    else:
        # show surrounding qwords
        ctx=pe[max(0,j-16):j+20]
        print("  bytes", ctx.hex())
    idx=j+1
