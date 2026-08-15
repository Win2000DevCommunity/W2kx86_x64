# Who calls setjmp on 5bb40 (1C65E)? And is it before waiter?
import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_lj.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
text=pe.sections[0].get_data(); base=0x1000
# callers of 1C65C area - find function start
print("=== 1C620-1C690 ===")
for i in md.disasm(pe.get_data(0x1C620, 0x80), 0x8001C620):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# Find calls to near 1C65C
target=0x1C640  # try function entry
# search backwards for push rbp / homes
