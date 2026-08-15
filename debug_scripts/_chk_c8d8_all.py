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
needle=struct.pack("<I", 0x4ad1c8d8)
idx=0
print("all refs to c8d8 abs:")
while True:
    j=blob.find(needle,idx)
    if j<0: break
    # find insn containing this
    found=False
    for back in range(0,8):
        for insn in md.disasm(blob[j-back:j-back+16], base32+va32+j-back, count=3):
            if needle.hex() in insn.bytes.hex() or "0x4ad1c8d8" in insn.op_str:
                left=insn.op_str.split(",")[0]
                kind="STORE" if ("ptr" in left or left.startswith("dword")) and insn.mnemonic.startswith(("mov","and","or","xor","add","sub","xchg")) and not left.startswith(("e","r")) else "OTHER"
                if insn.mnemonic=="mov" and "[" in left:
                    kind="STORE"
                if insn.mnemonic=="mov" and "[" in insn.op_str.split(",")[-1]:
                    kind="LOAD"
                if insn.mnemonic in ("push","call","cmp","test","lea"):
                    kind=insn.mnemonic.upper()
                print(f"  {insn.address-base32:#x}: {insn.mnemonic} {insn.op_str}  [{kind}]")
                found=True
                break
        if found: break
    idx=j+1
