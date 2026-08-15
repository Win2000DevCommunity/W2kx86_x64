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
# cmp ax, 0x3a
sig=bytes.fromhex("663d3a00")
hits=[]
i=rp
while True:
    j=pe.find(sig,i,rp+rs)
    if j<0: break
    hits.append(va+j-rp); i=j+1
print("cmp ax,3a", [hex(h) for h in hits[:30]])
sig2=bytes.fromhex("6683383a")  # cmp word [rax], 0x3a
hits=[]
i=rp
while True:
    j=pe.find(sig2,i,rp+rs)
    if j<0: break
    hits.append(va+j-rp); i=j+1
print("cmp word [rax],3a", [hex(h) for h in hits[:30]])
# also check 1d4fe area - is that wrongly used as f4eb?
print("\n==== 1d400-1d530 ====")
o=rp+(0x1d400-va)
for insn in md.disasm(pe[o:o+0x140], 0x80000000+0x1d400):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
