import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

# x86 source
src=open(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe","rb").read()
e=struct.unpack_from("<I",src,0x3c)[0]
n=struct.unpack_from("<H",src,e+6)[0]; opt=struct.unpack_from("<H",src,e+20)[0]; s0=e+24+opt
obase=struct.unpack_from("<I",src,e+24+28)[0]
for i in range(n):
    o=s0+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8); xt=src[rp:rp+rs]; xtr=va; break

# map pe64
rmap={}
for ln in open("build_univ88/rva.txt"):
    a=ln.split(); rmap[int(a[0],16)]=int(a[1],16)

# find x86 that maps near 0x14cf0
cands=[(x,p) for x,p in rmap.items() if 0x14c80 <= p <= 0x14d40]
cands.sort(key=lambda t:t[1])
print("map near 14cf0:")
for x,p in cands[:30]:
    print(f"  x86 {x:#x} -> {p:#x}")

# pick closest x86 for 14cf0
best=min(cands, key=lambda t: abs(t[1]-0x14cf0))
print("best", hex(best[0]), "->", hex(best[1]))

md=Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 around quote ===")
start=best[0]-0x40
for insn in md.disasm(xt[start-xtr:start-xtr+0xa0], obase+start):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}")

# pe64
pe=open(r"C:\Users\win2000\Desktop\univ88\cmd_pure.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3c)[0]
n=struct.unpack_from("<H",pe,e+6)[0]; opt=struct.unpack_from("<H",pe,e+20)[0]; s0=e+24+opt
for i in range(n):
    o=s0+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); text=pe[rp:rp+rs]; tva=va; break
md64=Cs(CS_ARCH_X86, CS_MODE_64)
print("\n=== pe64 around 14c80 ===")
off=0x14c80-tva
for insn in md64.disasm(text[off:off+0x100], 0x80000000+0x14c80):
    print(f"  {insn.address:#x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}")
