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
md = Cs(CS_ARCH_X86, CS_MODE_32)

for target in (0xefd6, 0xefe1, 0xf008, 0xff31):
    print(f"callers of {target:#x}:")
    for i in range(len(text)-5):
        if text[i] == 0xE8:
            rel = struct.unpack_from("<i", text, i+1)[0]
            tgt = (text_rva + i + 5 + rel) & 0xFFFFFFFF
            if tgt == target:
                print(f"  from {text_rva+i:#x}")

print("\n=== 0xefd6 function ===")
for insn in md.disasm(text[0xefd6-text_rva:0xf050-text_rva], base+0xefd6, count=40):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
