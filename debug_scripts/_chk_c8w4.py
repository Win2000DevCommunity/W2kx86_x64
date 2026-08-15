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
needle = struct.pack("<I", 0x4ad1c8d8)
# any insn using this imm - show if mov-to-mem via register soon after
pos = 0
addrs = []
while True:
    i = text.find(needle, pos)
    if i < 0: break
    addrs.append(text_rva+i)
    pos = i+1
print(f"{len(addrs)} raw occurrences")

# Look for mov reg, imm32 encoding B8+r / C7 C0+r
for i in range(len(text)-5):
    if text[i+1:i+5] == needle:
        op = text[i]
        if op in range(0xB8, 0xC0):  # mov r32, imm32
            print(f"  mov r32, c8d8 at {text_rva+i:#x} reg={op-0xB8}")
            for insn in md.disasm(text[i:i+40], base+text_rva+i, count=8):
                print(f"    {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
            print()
        elif op == 0xC7 and text[i+1] in range(0xC0, 0xC8):
            print(f"  mov r32,imm form2 at {text_rva+i:#x}")
