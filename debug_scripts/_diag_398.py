import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 3988E ===")
for i in md.disasm(pe.get_data(0x3988E, 0x80), 0x8003988E):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.address > 0x80039920:
        break

# Find x86 function that takes similar args - search for push 0x30 near table
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# utf16 table ( @ | in x86 .data
raw=x86.get_memory_mapped_image()
needle=b'(\x00\x00\x00@\x00\x00\x00|\x00'
idx=raw.find(needle)
print('x86 table at', hex(idx) if idx>=0 else None)

# Who in x86 calls with 0x30 and two function pointers - e.g. Dispatch
# pe64 1D5B4 function start
print("\n=== 1D5B4 ===")
for i in md.disasm(pe.get_data(0x1D5B4, 0x40), 0x8001D5B4):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
