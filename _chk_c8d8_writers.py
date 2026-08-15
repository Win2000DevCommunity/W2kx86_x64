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
    if name==b".rsrc": print("rsrc", hex(base32+va))

blob=src[raw32:raw32+rsz32]
md=Cs(CS_ARCH_X86,CS_MODE_32)
# stores to c8d8: a3 d8 c8 d1 4a or 89 xx
target=0x4ad1c8d8
pat=bytes([0xa3])+struct.pack("<I",target)
idx=0
print("mov [c8d8],eax sites:")
while True:
    j=blob.find(pat,idx)
    if j<0: break
    for insn in md.disasm(blob[max(0,j-0x20):j+6], base32+va32+max(0,j-0x20)):
        if insn.address >= base32+va32+j-0x18:
            print(f"  {insn.address-base32:#x}: {insn.mnemonic} {insn.op_str}")
    print("---")
    idx=j+1

# also 89 0d / 89 15 etc C7 05
for pref,lab in [(bytes([0xc7,0x05])+struct.pack("<I",target), "mov [c8d8],imm"),
                 (bytes([0x89,0x0d])+struct.pack("<I",target), "mov [c8d8],ecx"),
                 (bytes([0x89,0x15])+struct.pack("<I",target), "mov [c8d8],edx"),
                 (bytes([0x89,0x1d])+struct.pack("<I",target), "mov [c8d8],ebx"),
                 (bytes([0x89,0x35])+struct.pack("<I",target), "mov [c8d8],esi"),
                 (bytes([0x89,0x3d])+struct.pack("<I",target), "mov [c8d8],edi")]:
    idx=0
    while True:
        j=blob.find(pref,idx)
        if j<0: break
        print(f"{lab} @{va32+j:#x}")
        idx=j+1
