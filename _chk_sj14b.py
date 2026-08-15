from pathlib import Path
from tools.audit_calls import read_text_section
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

trva, data, _ = read_text_section(Path("build_univ14/cmd_pure.exe").read_bytes())
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("trva", hex(trva), "len", len(data))
for insn in md.disasm(data[0x1ac60-trva:0x1acd0-trva], 0x1ac60, count=40):
    print(f"  {insn.address:#07x}  {insn.bytes.hex():28s} {insn.mnemonic} {insn.op_str}")
