import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

data = Path("build_univ15/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", data, 0x3c)[0]
soh = struct.unpack_from("<H", data, e+20)[0]; sec = e+24+soh
num = struct.unpack_from("<H", data, e+6)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break

md=Cs(CS_ARCH_X86, CS_MODE_64)
needle=bytes.fromhex("49bb")+struct.pack("<Q", 0x8005fbc8)
i=0
while True:
    j=text.find(needle,i)
    if j<0: break
    insns=list(md.disasm(text[j:j+48], 0x80000000+text_rva+j, count=8))
    syn=" ; ".join(f"{x.mnemonic} {x.op_str}" for x in insns)
    # look for cmp word after load
    if "cmp word" in syn or (len(insns)>=3 and insns[2].mnemonic=="cmp"):
        print(f"{text_rva+j:#x}: {syn}")
    i=j+1
