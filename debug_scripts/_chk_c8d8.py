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

# refs to c8d8
print("=== stores to c8d8 ===")
pat=bytes([0xd8,0xc8,0xd1,0x4a])
idx=0
while True:
    i=xt.find(pat, idx)
    if i<0: break
    start=max(0,i-10)
    for insn in md.disasm(xt[start:i+6], obase+xtr+start, count=8):
        if b'\xd8\xc8\xd1\x4a' in insn.bytes or (insn.address-obase <= xtr+i <= insn.address-obase+len(insn.bytes)):
            if 'c8d8' in insn.op_str or '4ad1c8d8' in insn.op_str:
                print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
    idx=i+1

# Look at Init/startup that fills cmdline - search GetCommandLine usage
# IAT slot - find push of 24320 near GetCommandLine
print("\n=== around 0x23ff mov ebx, 24320 ===")
for insn in md.disasm(xt[0x23e0-xtr:0x23e0-xtr+0x80], obase+0x23e0):
    print(f"  {insn.address-obase:#07x}  {insn.mnemonic} {insn.op_str}")

print("\n=== around 0x40e4 ===")
for insn in md.disasm(xt[0x40c0-xtr:0x40c0-xtr+0xa0], obase+0x40c0):
    print(f"  {insn.address-obase:#07x}  {insn.mnemonic} {insn.op_str}")
