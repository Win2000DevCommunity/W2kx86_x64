import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== 1E2B4 full function-ish ===")
for i in md.disasm(pe.get_data(0x1E2B4, 0x120), 0x8001E2B4):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.mnemonic=='ret' and i.address>0x8001E350:
        break
