from pathlib import Path
from tools.audit_calls import read_text_section
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
trva,data,_=read_text_section(Path("build_univ13/cmd_pure.exe").read_bytes())
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("selfjmps", sum(1 for i in range(len(data)-5) if data[i]==0xE9 and data[i+1:i+5]==b"\xfb\xff\xff\xff"))
print("=== 0x7700 ===")
for insn in md.disasm(data[0x7700-trva:0x7730-trva], 0x7700, count=8):
    print(f"  {insn.address:#07x}  {insn.mnemonic} {insn.op_str}")
print("=== 0x33cd0 byte store ===")
for insn in md.disasm(data[0x33ce0-trva:0x33d00-trva], 0x33ce0, count=6):
    print(f"  {insn.address:#07x}  {insn.mnemonic} {insn.op_str}")
