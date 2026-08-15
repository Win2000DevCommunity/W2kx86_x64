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
print("=== x86 cursor init ~0xadc0 ===")
for insn in md.disasm(xt[0xad80-xtr:0xad80-xtr+0x120], obase+0xad80):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
    if insn.address-obase > 0xae80: break

# pe64 equivalent
rmap={}
for ln in open("build_univ88/rva.txt"):
    a=ln.split(); rmap[int(a[0],16)]=int(a[1],16)
print("\nmap ad80", hex(rmap.get(0xad80,-1)), "ae1e", hex(rmap.get(0xae1e,-1)))

pe=open(r"C:\Users\win2000\Desktop\univ88\cmd_pure.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3c)[0]
n=struct.unpack_from("<H",pe,e+6)[0]; opt=struct.unpack_from("<H",pe,e+20)[0]; s0=e+24+opt
for i in range(n):
    o=s0+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); text=pe[rp:rp+rs]; tva=va; break

# find movabs 0x80071320
pat=struct.pack('<Q', 0x80071320)
idx=0
print("\nrefs to 0x80071320:")
while True:
    i=pe.find(pat, idx)
    if i<0: break
    # rva
    for j in range(n):
        o=s0+j*40
        vs,sva,srsz,sraw=struct.unpack_from("<IIII",pe,o+8)
        if sraw <= i < sraw+srsz:
            rva=sva+(i-sraw)
            name=pe[o:o+8].split(b'\0')[0]
            print(f"  {name} rva {rva:#x} file {i:#x}")
            if name==b'.text':
                off=rva-tva
                md64=Cs(CS_ARCH_X86, CS_MODE_64)
                for insn in md64.disasm(text[max(0,off-16):off+24], 0x80000000+rva-min(16,off), count=8):
                    print(f"    {insn.address:#x}  {insn.mnemonic} {insn.op_str}")
            break
    idx=i+1

# also search who writes to cursor - pe64 store patterns around map ae1e
ae=rmap.get(0xae1e,0)
print("\n=== pe64 at ae1e map", hex(ae), "===")
md64=Cs(CS_ARCH_X86, CS_MODE_64)
off=ae-tva-0x40
for insn in md64.disasm(text[off:off+0x100], 0x80000000+ae-0x40):
    print(f"  {insn.address:#x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
