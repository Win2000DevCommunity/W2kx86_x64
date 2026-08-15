import struct
from x86x64.translator.core import X86toX64Translator
# Check if we can load and translate one function - might be heavy.
# Instead inspect univ88 build for intermediate? 
# Compare: what does _relocate_imm give for these VAs with section map from a built translator state?

# Simpler: scan ALL movabs in adad region and also search if 0x4ad1fbe2 or 0x8001fbe2 still appears anywhere near
pe=open(r"C:\Users\win2000\Desktop\univ88\cmd_pure.exe","rb").read()
for va in (0x4ad1fbe2, 0x8001fbe2, 0x8006cbe2, 0x4ad21820, 0x8006e820, 0x4ad22844, 0x8006f844, 0x4ad21000, 0x8006e000):
    c=pe.count(struct.pack('<Q', va))
    print(hex(va), c)

# Disasm a few instructions BEFORE adad in pe64 - is there overlapping corruption?
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
e=struct.unpack_from("<I",pe,0x3c)[0]
n=struct.unpack_from("<H",pe,e+6)[0]; opt=struct.unpack_from("<H",pe,e+20)[0]; s0=e+24+opt
for i in range(n):
    o=s0+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); text=pe[rp:rp+rs]; tva=va; break
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("--- before adad ---")
for insn in md.disasm(text[0x14620-tva:0x14648-tva], 0x80014620):
    print(f"  {insn.address:#x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")
