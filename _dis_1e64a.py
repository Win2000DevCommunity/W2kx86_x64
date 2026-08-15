import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== 1E64A body after callback ===")
for i in md.disasm(pe.get_data(0x1E64A, 0x100), 0x8001E64A):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.mnemonic=='ret' or (i.mnemonic=='jmp' and i.address>0x8001E740):
        break
