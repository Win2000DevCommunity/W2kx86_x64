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
# find function containing ae1e - look for push ebp near
print("=== x86 0xadad (known parse) ===")
for insn in md.disasm(xt[0xadad-xtr:0xadad-xtr+0xc0], obase+0xadad):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
    if insn.address-obase > 0xae50: break

# What is 0x4ad21000 and 0x4ad24320 in x86?
print("\n=== refs to 21000 / 24320 / 21840 / fbe0 ===")
for addr in (0x4ad21000, 0x4ad24320, 0x4ad21840, 0x4ad1fbe0, 0x4ad1fbc8):
    pat=struct.pack('<I', addr)
    idx=0; c=0
    while c<8:
        i=xt.find(pat, idx)
        if i<0: break
        rva=xtr+i
        # decode insn start roughly - show nearby
        start=max(0,i-6)
        for insn in md.disasm(xt[start:i+6], obase+xtr+start, count=5):
            if addr.to_bytes(4,'little') in insn.bytes:
                print(f"  {insn.address-obase:#07x}  {insn.mnemonic} {insn.op_str}")
                break
        idx=i+1; c+=1

# Live: dump 0x8006e000 and related at parse
