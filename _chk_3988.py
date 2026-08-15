import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ238/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
off=rp+(0x39870-va)
print(pe[off:off+0x50].hex())
for insn in md.disasm(pe[off:off+0x50], 0x80000000+0x39870):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# what is at 594f6 - is it a function pointer slot that should be filled?
# find xrefs to 0x594f6 or nearby
target=struct.pack("<I",0x594f6)
# also check movabs of 800594f6
pat=struct.pack("<Q",0x800594f6)
hits=[]
i=rp
while True:
    j=pe.find(pat,i,rp+rs)
    if j<0: break
    hits.append(va+j-rp); i=j+1
print("movabs 800594f6 at", [hex(h) for h in hits[:20]])
# find call [something] near 39888
