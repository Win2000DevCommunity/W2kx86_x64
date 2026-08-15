import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
# look for mov eax, esi; pop rsi; ret near 45a80
print("=== 45A80-45B00 ===")
for i in md.disasm(pe.get_data(0x45A80, 0x80), 0x80045A80):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# search 89 f0 5e c3 or 89 f0 5e 
text=pe.get_data(0x45800, 0x400)
import struct
for off in range(len(text)-4):
    if text[off:off+3] in (bytes.fromhex("89f05e"), bytes.fromhex("8bf05e")):
        print("hit", hex(0x45800+off), text[off:off+6].hex())
