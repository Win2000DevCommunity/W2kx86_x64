import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

data=Path("build_univ20/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
base=struct.unpack_from("<Q", data, e+24+24)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break
md=Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
# any call to 0x2480-0x24b0
print("All calls to 0x2480-0x24c0:")
for insn in md.disasm(text, base+text_rva):
    if insn.mnemonic!="call": continue
    if not insn.op_str.startswith("0x"): continue
    tgt=int(insn.op_str,16)-base
    if 0x2480 <= tgt <= 0x24c0:
        print(f"  {insn.address-base:#07x} -> {tgt:#x}  {insn.bytes.hex()}")

# Also jmp to that range
print("Jmps to 0x2480-0x24c0:")
for insn in md.disasm(text, base+text_rva):
    if insn.mnemonic!="jmp": continue
    if not insn.op_str.startswith("0x"): continue
    tgt=int(insn.op_str,16)-base
    if 0x2480 <= tgt <= 0x24c0:
        print(f"  {insn.address-base:#07x} -> {tgt:#x}")

# What about calls to 0x1490 range if coords wrong? skip

# Trace: who could land on 2491 - search rel32 that decode to it
print("\nE8 bytes targeting ~0x2491:")
for i in range(len(text)-5):
    if text[i]!=0xE8: continue
    rel=struct.unpack_from("<i", text, i+1)[0]
    tgt=(text_rva+i+5+rel)&0xffffffff
    # tgt as pe rva
    if 0x2488 <= tgt <= 0x24a0:
        print(f"  site pe {text_rva+i:#x} -> {tgt:#x}")
