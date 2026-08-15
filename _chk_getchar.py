import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

pe=open(r"C:\Users\win2000\Desktop\univ88\cmd_pure.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3c)[0]
n=struct.unpack_from("<H",pe,e+6)[0]; opt=struct.unpack_from("<H",pe,e+20)[0]; s0=e+24+opt
secs={}
for i in range(n):
    o=s0+i*40
    name=pe[o:o+8].split(b'\0')[0].decode()
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
    secs[name]=(va,vs,rp,rs)
    print(f"{name:8} va={va:#x} vsz={vs:#x} raw={rp:#x}")

# what's at rva 0x71320?
rva=0x71320
for name,(va,vs,rp,rs) in secs.items():
    if va <= rva < va+vs:
        off=rp+(rva-va)
        print(f"\n0x{rva:x} in {name}, file off {off:#x}")
        print("bytes", pe[off:off+32].hex())
        break

# disasm get-next-char at 0x55ef8
text=pe[secs['.text'][2]:secs['.text'][2]+secs['.text'][3]]; tva=secs['.text'][0]
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("\n=== pe64 getchar 0x55ef8 ===")
off=0x55ef8-tva
for insn in md.disasm(text[off:off+0x80], 0x80000000+0x55ef8):
    print(f"  {insn.address:#x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}")
    if insn.address > 0x80055ef8+0x60: break

# x86 getchar at 0xb186
src=open(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe","rb").read()
e=struct.unpack_from("<I",src,0x3c)[0]
n=struct.unpack_from("<H",src,e+6)[0]; opt=struct.unpack_from("<H",src,e+20)[0]; s0=e+24+opt
obase=struct.unpack_from("<I",src,e+24+28)[0]
for i in range(n):
    o=s0+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8); xt=src[rp:rp+rs]; xtr=va; break
md32=Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 getchar 0xb186 ===")
for insn in md32.disasm(xt[0xb186-xtr:0xb186-xtr+0x60], obase+0xb186):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}")

# rva map for b186
rmap={}
for ln in open("build_univ88/rva.txt"):
    a=ln.split(); rmap[int(a[0],16)]=int(a[1],16)
print("\nmap b186", hex(rmap.get(0xb186, -1)))
print("map b00c", hex(rmap.get(0xb00c, -1)))
print("map add9", hex(rmap.get(0xadd9, -1)))
print("map afb4", hex(rmap.get(0xafb4, -1)))

# disasm parse function start x86 from ~0xadd9 or 0xb000
print("\n=== x86 parse start 0xaf80 ===")
for insn in md32.disasm(xt[0xaf80-xtr:0xaf80-xtr+0x100], obase+0xaf80):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}")
    if insn.address-obase > 0xb020: break
