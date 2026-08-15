import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_lj.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== waiter ===")
for i in md.disasm(pe.get_data(0x45820, 0x40), 0x80045820):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str} [{i.bytes.hex()}]")

print("\n=== 474FC (longjmp non-zero path) ===")
for i in md.disasm(pe.get_data(0x474FC, 0x60), 0x800474FC):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.address > 0x80047550:
        break

# x86 after setjmp when eax != 0
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("\n=== x86 EF64 setjmp continuation ===")
for i in md32.disasm(x86.get_data(0xEF64, 0x80), 0xEF64):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
