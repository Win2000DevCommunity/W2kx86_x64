import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

src=open(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe","rb").read()
e=struct.unpack_from("<I",src,0x3c)[0]
n=struct.unpack_from("<H",src,e+6)[0]; opt=struct.unpack_from("<H",src,e+20)[0]; s0=e+24+opt
obase=struct.unpack_from("<I",src,e+24+28)[0]
for i in range(n):
    o=s0+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8); xt=src[rp:rp+rs]; xtr=va; break
md=Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 ae2a..ae45 ===")
for insn in md.disasm(xt[0xae2a-xtr:0xae2a-xtr+0x30], obase+0xae2a):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")

pe=open(r"C:\\Users\\win2000\\Desktop\\univ89\\cmd_pure.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3c)[0]
n=struct.unpack_from("<H",pe,e+6)[0]; opt=struct.unpack_from("<H",pe,e+20)[0]; s0=e+24+opt
for i in range(n):
    o=s0+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); text=pe[rp:rp+rs]; tva=va; break
rmap={}
for ln in open("build_univ89/rva.txt"):
    a=ln.split(); rmap[int(a[0],16)]=int(a[1],16)
md64=Cs(CS_ARCH_X86, CS_MODE_64)
print("\n=== pe64 map ae2a.. ===")
off=rmap[0xae2a]-tva
for insn in md64.disasm(text[off:off+0x50], 0x80000000+rmap[0xae2a]):
    print(f"  {insn.address:#x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")

# How many test [ebp+0xc] in x86?
print("\n=== x86 test byte [ebp+0xc] sites ===")
# F6 45 0C xx
idx=0; c=0
while c<20:
    i=xt.find(b'\xf6\x45\x0c', idx)
    if i<0: break
    rva=xtr+i
    print(f"  {rva:#x} imm={xt[i+3]:#x} -> pe64 {hex(rmap.get(rva,-1))}")
    idx=i+1; c+=1
