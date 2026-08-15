import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== 14974 GetInput ===")
for i in md.disasm(pe.get_data(0x14974, 0x80), 0x80014974):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.address > 0x80014A00:
        break

# Count how deep: use HW BP on 1E2B4 entry and count hits before crash
