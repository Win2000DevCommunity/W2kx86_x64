from pathlib import Path
from tools.audit_calls import read_text_section, load_map
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct

rmap = load_map(Path("build_univ14/rva.txt"))
trva, data, _ = read_text_section(Path("build_univ14/cmd_pure.exe").read_bytes())
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("x86 0xef69 setjmp call map", hex(rmap.get(0xef69, 0)))
print("x86 0xef64 map", hex(rmap.get(0xef64, 0)))
for o in range(0xef50, 0xef80):
    if o in rmap:
        print(f"  {o:#x} -> {rmap[o]:#x}")

xr = rmap.get(0xef5b) or rmap.get(0xef61) or rmap.get(0xef40)
print("\ndisasm from", hex(xr or 0))
if xr:
    for insn in md.disasm(data[xr-trva:xr-trva+120], xr, count=35):
        print(f"  {insn.address:#07x}  {insn.bytes.hex():28s} {insn.mnemonic} {insn.op_str}")

# Count align+setjmp patterns: push r13; ... call near movabs of setjmp iat
# setjmp iat from univ13 was 0x80089ef8 - find in univ14
print("\nsearch movabs to setjmp-like then call")
