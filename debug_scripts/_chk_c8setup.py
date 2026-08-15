import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src=open(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe","rb").read()
e=struct.unpack_from("<I",src,0x3c)[0]
n=struct.unpack_from("<H",src,e+6)[0]; opt=struct.unpack_from("<H",src,e+20)[0]; s0=e+24+opt
obase=struct.unpack_from("<I",src,e+24+28)[0]
for i in range(n):
    o=s0+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8); xt=src[rp:rp+rs]; xtr=va; break
md=Cs(CS_ARCH_X86, CS_MODE_32)

# Find function that sets up cmdline - search for mov [c8d8], reg near 24320
# Also look at CheckSwitches / parse cmdline around 0xf000
print("=== x86 0xeff0..0xf0a0 ===")
for insn in md.disasm(xt[0xeff0-xtr:0xeff0-xtr+0xb0], obase+0xeff0):
    print(f"  {insn.address-obase:#07x}  {insn.mnemonic} {insn.op_str}")

print("\n=== x86 refs storing TO c8d8 (a3/890d) ===")
# a3 d8 c8 d1 4a or 890d d8 c8 d1 4a
for pat in [bytes([0xa3,0xd8,0xc8,0xd1,0x4a]), bytes([0x89,0x0d,0xd8,0xc8,0xd1,0x4a]),
            bytes([0x89,0x15,0xd8,0xc8,0xd1,0x4a]), bytes([0x89,0x35,0xd8,0xc8,0xd1,0x4a])]:
    idx=0
    while True:
        i=xt.find(pat, idx)
        if i<0: break
        rva=xtr+i
        start=max(0,i-30)
        print(f"--- store at {rva:#x} ---")
        for insn in md.disasm(xt[start:i+8], obase+xtr+start, count=12):
            print(f"  {insn.address-obase:#07x}  {insn.mnemonic} {insn.op_str}")
        idx=i+1
