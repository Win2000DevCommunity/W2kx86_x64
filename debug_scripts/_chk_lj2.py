from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from tools.audit_calls import read_text_section, load_map
import struct

rmap=load_map(Path("build_univ11/rva.txt"))
trva,data,_=read_text_section(Path("build_univ11/cmd_pure.exe").read_bytes())
md=Cs(CS_ARCH_X86, CS_MODE_64)

print("maps around 0xf00f:")
for o in range(0xf000, 0xf040):
    if o in rmap:
        print(f"  {o:#07x} -> {rmap[o]:#07x}")

# Find longjmp IAT call with rcx=0x80060b40 and rdx=-1
# Search for movabs rcx, 0x80060b40 near longjmp
pat=struct.pack("<Q", 0x80060b40)
idx=0
print("\nfull contexts for 0x80060b40:")
while True:
    i=data.find(pat, idx)
    if i<0: break
    start=max(0,i-16)
    print(f"\n--- @ {trva+i:#x} ---")
    for insn in md.disasm(data[start:i+48], trva+start, count=12):
        print(f"  {insn.address:#07x}  {insn.bytes.hex():24s} {insn.mnemonic} {insn.op_str}")
    idx=i+1

# longjmp IAT slot?
# From earlier call was via [0x4ad011d4] - find x64 IAT for longjmp
print("\n=== looking for longjmp thunk calls near ae0 ===")
pat_ae0=struct.pack("<Q", 0x80060ae0)
idx=0
while True:
    i=data.find(pat_ae0, idx)
    if i<0: break
    start=max(0,i-8)
    print(f"\n--- ae0 @ {trva+i:#x} ---")
    for insn in md.disasm(data[start:i+64], trva+start, count=15):
        print(f"  {insn.address:#07x}  {insn.bytes.hex():24s} {insn.mnemonic} {insn.op_str}")
    idx=i+1
