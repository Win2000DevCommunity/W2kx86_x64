from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3C)[0]
base=struct.unpack_from("<I",src,e+24+28)[0]
nsec=struct.unpack_from("<H",src,e+6)[0]
osz=struct.unpack_from("<H",src,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    name=src[off:off+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",src,off+8)
    if name==b".text": va32,raw32,rsz32=va,raw,rsz
blob=src[raw32:raw32+rsz32]
# find push 0x40; push ???; call add9  or push reg with 0x40
# simpler: disasm ff49 caller area and fdbe
md=Cs(CS_ARCH_X86,CS_MODE_32)
for start in (0xff31, 0xac4f, 0xba47):
    print(f"=== {start:#x} ===")
    fo=raw32+(start-va32)
    for insn in md.disasm(src[fo:fo+0x50], base+start):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if insn.address>base+start+0x40: break
