from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3C)[0]
base32=struct.unpack_from("<I",src,e+24+28)[0]
nsec=struct.unpack_from("<H",src,e+6)[0]
osz=struct.unpack_from("<H",src,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    name=src[off:off+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",src,off+8)
    if name==b".text": va32,raw32,rsz32=va,raw,rsz
blob=src[raw32:raw32+rsz32]
md=Cs(CS_ARCH_X86,CS_MODE_32)
# scan all insns for store to c8d8
print("scanning stores...")
for insn in md.disasm(blob, base32+va32):
    if "0x4ad1c8d8" not in insn.op_str: continue
    left=insn.op_str.split(",")[0].strip()
    if "[" in left:
        print(f"  {insn.address-base32:#x}: {insn.mnemonic} {insn.op_str}")
