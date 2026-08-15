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
print("=== around 0x10060 ===")
for insn in md.disasm(text[0x10050-text_rva:0x10090-text_rva], base+0x10050, count=25):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
print("=== around 0xef60 setjmp ===")
for insn in md.disasm(text[0xef40-text_rva:0xef90-text_rva], base+0xef40, count=30):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
