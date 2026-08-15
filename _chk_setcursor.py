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
print("=== x86 0xb5e0..0xb650 (sets fbc8) ===")
for insn in md.disasm(xt[0xb5e0-xtr:0xb5e0-xtr+0x80], obase+0xb5e0):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")

# Also search: mov [fbc8], reg where source might be c8d8 or 24320
print("\n=== mov to fbc8 ===")
pat=struct.pack('<I', 0x4ad1fbc8)
idx=0
while True:
    i=xt.find(pat, idx)
    if i<0: break
    start=max(0,i-10)
    for insn in md.disasm(xt[start:i+6], obase+xtr+start, count=8):
        if 'fbc8' in insn.op_str or '4ad1fbc8' in insn.op_str:
            if insn.mnemonic=='mov' and insn.op_str.startswith('dword ptr'):
                print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
                # show prev 3
                for insn2 in md.disasm(xt[max(0,insn.address-obase-xtr-15):insn.address-obase-xtr], obase+insn.address-15, count=5):
                    print(f"    prev {insn2.address-obase:#07x}  {insn2.mnemonic} {insn2.op_str}")
    idx=i+1
