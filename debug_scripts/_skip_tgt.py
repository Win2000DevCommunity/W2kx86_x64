# Find pe64 of x86 f81b via searching call pattern near end
# x86 10005 - what is it?
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 10005 ===")
for i in md32.disasm(x86.get_data(0x10005, 0x30), 0x10005):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")

# In pe64 search for mov dword [rsi], 0x39 nearby then later path
pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
# after 459CC - maybe wrong. Look for pop rsi; ret after 45894 function
print("\n=== scan forward for ret ===")
for i in md.disasm(pe.get_data(0x459C0, 0x80), 0x800459C0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.mnemonic=='ret' and i.address > 0x800459C0:
        break
