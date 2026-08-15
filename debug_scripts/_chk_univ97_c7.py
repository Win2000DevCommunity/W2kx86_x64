from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct
pe=Path("build_univ97/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
base=struct.unpack_from("<Q",pe,e+24+24)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    if pe[off:off+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8); break
print("lin_fbe2 dword count", pe.count(struct.pack("<I",0x8001fbe2)))
print("ok_fbe2 dword count", pe.count(struct.pack("<I",0x8006cbe2)))
# show C7 store at previous bad site if still there
code=pe[rp:rp+rs]
# find c700 with either imm
for imm in (0x8001fbe2, 0x8006cbe2):
    pat=b"\xc7\x00"+struct.pack("<I",imm)
    idx=0
    while True:
        j=code.find(pat,idx)
        if j<0: break
        print(f"  c700 {imm:#x} @{va+j:#x}")
        idx=j+1
# disasm around 565be
md=Cs(CS_ARCH_X86,CS_MODE_64)
off=0x565b4-va
for insn in md.disasm(code[off:off+0x30], base+0x565b4):
    print(f"  {insn.address-base:#x}: {insn.mnemonic} {insn.op_str}")
