import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 1EA3C ===")
for i in md.disasm(pe.get_data(0x1EA3C, 0x40), 0x8001EA3C):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
# follow jmp if any
b = pe.get_data(0x1EA3C, 5)
if b[0]==0xE9:
    rel=struct.unpack_from("<i", b, 1)[0]
    cave=0x1EA3C+5+rel
    print("cave", hex(cave))
    for i in md.disasm(pe.get_data(cave, 0x50), 0x80000000+cave):
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

print("\n=== callers of 14974 ===")
text = pe.get_data(0x1000, 0x57000)
target = 0x14974 - 0x1000
for off in range(len(text)-5):
    if text[off]!=0xE8: continue
    rel=struct.unpack_from("<i", text, off+1)[0]
    if off+5+rel == target:
        print(hex(off+0x1000))
