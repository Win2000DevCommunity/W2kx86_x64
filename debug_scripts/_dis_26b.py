import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ257/cmd_probe_exit2.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== pe64 26B80-26C20 ===")
for i in md.disasm(pe.get_data(0x26B80, 0xA0), 0x80026B80):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# map back - search x86 for similar
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
# AC92 callers in x86 - find call ac92
import struct
text = x86.get_data(0x1000, 0x1A000)
# rough: E8 rel to ac92
target = 0xAC92
for off in range(len(text)-5):
    if text[off] != 0xE8: continue
    rel = struct.unpack_from("<i", text, off+1)[0]
    if off + 0x1000 + 5 + rel == target:
        rva = off + 0x1000
        print("x86 call AC92 from", hex(rva))
