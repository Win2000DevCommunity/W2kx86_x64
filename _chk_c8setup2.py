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

# any instruction containing c8d8 as immediate that writes
pat=struct.pack('<I', 0x4ad1c8d8)
idx=0; stores=[]
while True:
    i=xt.find(pat, idx)
    if i<0: break
    # decode from i-6
    start=max(0,i-8)
    for insn in md.disasm(xt[start:i+6], obase+xtr+start, count=6):
        if 0x4ad1c8d8 in insn.bytes or pat in insn.bytes:
            if insn.mnemonic=='mov' and '0x4ad1c8d8' in insn.op_str and insn.op_str.startswith('dword ptr'):
                stores.append(insn)
            elif insn.mnemonic in ('mov','lea') and '0x4ad1c8d8' in insn.op_str:
                print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
    idx=i+1

print("store-like count detailed above")

# Look at GetCommandLine usage - IAT call then store
# pe64: who writes to 6c9d8 (c8d8 remap)
pe=open(r"C:\Users\win2000\Desktop\univ89\cmd_pure.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3c)[0]
n=struct.unpack_from("<H",pe,e+6)[0]; opt=struct.unpack_from("<H",pe,e+20)[0]; s0=e+24+opt
for i in range(n):
    o=s0+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); text=pe[rp:rp+rs]; tva=va; break
md64=Cs(CS_ARCH_X86, CS_MODE_64)
pat=struct.pack('<Q', 0x8006c9d8)
idx=0; c=0
print("\npe64 refs to c8d8 slot 0x8006c9d8:")
while c<15:
    i=text.find(pat, idx)
    if i<0: break
    rva=tva+i
    # show surrounding
    for insn in md64.disasm(text[max(0,i-20):i+20], 0x80000000+rva-min(20,i), count=10):
        if insn.address <= 0x80000000+rva+8:
            print(f"  {insn.address:#x}  {insn.mnemonic} {insn.op_str}")
    print("---")
    idx=i+1; c+=1
