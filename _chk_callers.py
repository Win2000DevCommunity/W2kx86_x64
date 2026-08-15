import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]; soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
for i in range(num):
    o = sec+i*40
    if src[o:o+5] == b".text":
        va, rs, rp = struct.unpack_from("<III", src, o+12)
        text = src[rp:rp+rs]; text_rva = va; break
base = struct.unpack_from("<I", src, e+24+28)[0]

# Find E8 calls to 0xef42
target = 0xef42
print("callers of 0xef42:")
for i in range(len(text)-5):
    if text[i] == 0xE8:
        rel = struct.unpack_from("<i", text, i+1)[0]
        tgt = (text_rva + i + 5 + rel) & 0xFFFFFFFF
        if tgt == target:
            print(f"  from {text_rva+i:#x}")

# Also 0xefe1 callers  
print("callers of 0xefe1:")
for i in range(len(text)-5):
    if text[i] == 0xE8:
        rel = struct.unpack_from("<i", text, i+1)[0]
        tgt = (text_rva + i + 5 + rel) & 0xFFFFFFFF
        if tgt == 0xefe1:
            print(f"  from {text_rva+i:#x}")

# What about 0xef40 as entry - maybe 0xef42 is mid-nop
md = Cs(CS_ARCH_X86, CS_MODE_32)
print("\nfunc before ef42:")
for insn in md.disasm(text[0xef20-text_rva:0xef50-text_rva], base+0xef20, count=20):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
