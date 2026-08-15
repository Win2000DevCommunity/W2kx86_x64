import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe=open(r"C:\Users\win2000\Desktop\univ89\cmd_pure.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3c)[0]
n=struct.unpack_from("<H",pe,e+6)[0]; opt=struct.unpack_from("<H",pe,e+20)[0]; s0=e+24+opt
for i in range(n):
    o=s0+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); text=pe[rp:rp+rs]; tva=va; break
md=Cs(CS_ARCH_X86, CS_MODE_64)

# Find movabs 6c9d8 followed within 40 bytes by store involving 6cbc8
pat_c8=struct.pack('<Q', 0x8006c9d8)
pat_cur=struct.pack('<Q', 0x8006cbc8)
idx=0; found=0
while found<20:
    i=text.find(pat_c8, idx)
    if i<0: break
    window=text[i:i+60]
    if pat_cur in window:
        rva=tva+i
        print(f"=== near {rva:#x} ===")
        for insn in md.disasm(text[max(0,i-10):i+50], 0x80000000+rva-min(10,i), count=15):
            print(f"  {insn.address:#x}  {insn.mnemonic} {insn.op_str}")
        found+=1
    idx=i+1
print("found", found)

# Also: does pe64 add9 when esi!=0 set cursor from rsi? Check 1474d path
rmap={}
for ln in open("build_univ89/rva.txt"):
    a=ln.split(); rmap[int(a[0],16)]=int(a[1],16)
print("\n=== pe64 add9 esi!=0 path ===")
off=rmap[0xae2a]-tva
for insn in md.disasm(text[off:off+0x40], 0x80000000+rmap[0xae2a]):
    print(f"  {insn.address:#x}  {insn.mnemonic} {insn.op_str}")
