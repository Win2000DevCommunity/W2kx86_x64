from pathlib import Path
from tools.audit_calls import read_text_section
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
trva,data,_=read_text_section(Path("build_univ3/cmd_pure.exe").read_bytes())
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("=== univ3 call arg setup ===")
for ins in md.disasm(data[0x49a60-trva:0x49ad5-trva], 0x49a60):
    print(hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str)
