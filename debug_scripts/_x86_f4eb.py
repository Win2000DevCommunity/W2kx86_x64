import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("=== F4EB-F5A0 ===")
for i in md32.disasm(x86.get_data(0xF4EB, 0xB8), 0xF4EB):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")

# event create - search CreateEvent
print("\n=== CreateEvent IAT uses near init ===")
