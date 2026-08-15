import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

src=open(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe","rb").read()
e=struct.unpack_from("<I",src,0x3c)[0]
n=struct.unpack_from("<H",src,e+6)[0]; opt=struct.unpack_from("<H",src,e+20)[0]; s0=e+24+opt
obase=struct.unpack_from("<I",src,e+24+28)[0]
print("obase", hex(obase))
for i in range(n):
    o=s0+i*40
    name=src[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8)
    print(f"{name} va={va:#x} vs={vs:#x}")
    if name.startswith(b".text"):
        xt=src[rp:rp+rs]; xtr=va
    if name.startswith(b".data"):
        data=src[rp:rp+rs]; dva=va

# x86 refill b21c
md=Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 refill 0xb21c ===")
for insn in md.disasm(xt[0xb21c-xtr:0xb21c-xtr+0x120], obase+0xb21c):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
    if insn.address-obase > 0xb2f0: break

# who writes fbc8 cursor?
print("\n=== refs to fbc8 in x86 ===")
# search 8b0dc8fbd14a or 890dc8fbd14a or a1c8fbd14a
pat=bytes([0xc8,0xfb,0xd1,0x4a])
idx=0
while True:
    i=xt.find(pat, idx)
    if i<0: break
    rva=xtr+i
    # show context
    start=max(0,i-8)
    for insn in md.disasm(xt[start:i+8], obase+xtr+start, count=6):
        if insn.address-obase >= rva-2 and insn.address-obase <= rva+2:
            print(f"  {insn.address-obase:#07x}  {insn.mnemonic} {insn.op_str}")
    idx=i+1

# pe64 refill 14f48
pe=open(r"C:\Users\win2000\Desktop\univ88\cmd_pure.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3c)[0]
n=struct.unpack_from("<H",pe,e+6)[0]; opt=struct.unpack_from("<H",pe,e+20)[0]; s0=e+24+opt
for i in range(n):
    o=s0+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); text=pe[rp:rp+rs]; tva=va; break
md64=Cs(CS_ARCH_X86, CS_MODE_64)
print("\n=== pe64 refill 0x14f48 ===")
off=0x14f48-tva
for insn in md64.disasm(text[off:off+0x150], 0x80000000+0x14f48):
    print(f"  {insn.address:#x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
    if insn.address > 0x80014f48+0x130: break

# map
rmap={}
for ln in open("build_univ88/rva.txt"):
    a=ln.split(); rmap[int(a[0],16)]=int(a[1],16)
print("\nmap b21c", hex(rmap.get(0xb21c,-1)))
