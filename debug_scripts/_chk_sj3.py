import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from tools.audit_calls import read_text_section, load_map

trva,data,_=read_text_section(Path("build_univ11/cmd_pure.exe").read_bytes())
md=Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
print("=== x64 around fb40 setjmp (0x1adc0) ===")
for insn in md.disasm(data[0x1adc0-trva:0x1ae40-trva], 0x1adc0, count=40):
    print(f"{insn.address:#07x}  {insn.bytes.hex():24s} {insn.mnemonic} {insn.op_str}")

print("\n=== x64 around longjmp site (0x1d1f0 from earlier path) ===")
# find cmp [0x80060ae0]
pat=struct.pack("<Q", 0x80060ae0)
i=data.find(pat)
print(f"first ae0 ref at {trva+i:#x}")
start=max(0,i-20)
for insn in md.disasm(data[start:i+40], trva+start, count=20):
    print(f"{insn.address:#07x}  {insn.bytes.hex():24s} {insn.mnemonic} {insn.op_str}")
