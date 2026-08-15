import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ259/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 34140 ===")
for i in md.disasm(pe.get_data(0x34140, 0x50), 0x80034140):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# 624A0 in .data?
print("\n.data at 624A0:", pe.get_data(0x624A0, 32).hex())
import struct
print("as qwords:", [hex(struct.unpack_from('<Q', pe.get_data(0x624A0, 32), i)[0]) for i in range(0,32,8)])

# 59580
print("\n59580:", pe.get_data(0x59580, 32)[:32])
try:
    print(pe.get_data(0x59580, 64).decode('utf-16-le','replace')[:40])
except: pass

# Check shim longjmp has movsxd
shim = pefile.PE("build_univ259/w2kshim64.dll")
for exp in shim.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name == b"longjmp":
        blob = shim.get_data(exp.address, 0x50)
        print("longjmp has movsxd", b"\x48\x63\xc2" in blob, blob.hex()[-40:])
