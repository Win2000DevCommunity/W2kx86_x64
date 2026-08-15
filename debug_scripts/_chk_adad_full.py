import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

pe=open(r"C:\Users\win2000\Desktop\univ88\cmd_pure.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3c)[0]
n=struct.unpack_from("<H",pe,e+6)[0]; opt=struct.unpack_from("<H",pe,e+20)[0]; s0=e+24+opt
for i in range(n):
    o=s0+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); text=pe[rp:rp+rs]; tva=va; break
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("=== FULL pe64 adad ===")
for insn in md.disasm(text[0x14648-tva:0x14648-tva+0x60], 0x80014648):
    print(f"  {insn.address:#x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
    if insn.address>=0x8001469c: break

# Who calls ADD9 with ret 0x8001c27a?
rmap={}
for ln in open("build_univ88/rva.txt"):
    a=ln.split(); rmap[int(a[0],16)]=int(a[1],16)
rev={v:k for k,v in rmap.items()}
print("x86 for 1c27a", hex(rev.get(0x1c27a, -1)))
# find nearest
cands=sorted([(abs(v-0x1c27a),k,v) for k,v in rmap.items()])[:5]
print("nearest", [(hex(k),hex(v)) for _,k,v in cands])

# disasm pe64 caller around 1c200
print("\n=== pe64 caller ~1c200 ===")
for insn in md.disasm(text[0x1c200-tva:0x1c200-tva+0x100], 0x8001c200):
    print(f"  {insn.address:#x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")

# x86 around ff49
src=open(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe","rb").read()
e=struct.unpack_from("<I",src,0x3c)[0]
n=struct.unpack_from("<H",src,e+6)[0]; opt=struct.unpack_from("<H",src,e+20)[0]; s0=e+24+opt
obase=struct.unpack_from("<I",src,e+24+28)[0]
for i in range(n):
    o=s0+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8); xt=src[rp:rp+rs]; xtr=va; break
md32=Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 ff20..ff60 ===")
for insn in md32.disasm(xt[0xff20-xtr:0xff20-xtr+0x50], obase+0xff20):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
