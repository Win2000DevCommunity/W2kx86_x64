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
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
needle = struct.pack("<I", 0x4ad1c8d8)
pos = 0
while True:
    i = text.find(needle, pos)
    if i < 0: break
    start = max(0, i-6)
    insns = list(md.disasm(text[start:i+8], base+text_rva+start, count=4))
    for insn in insns:
        if needle not in insn.bytes:
            continue
        # Capstone detail: mem operand with disp == c8d8
        for op in insn.operands:
            if op.type == 3:  # MEM
                if (op.mem.disp & 0xFFFFFFFF) == 0x4ad1c8d8 and op.mem.base == 0:
                    # is it destination?
                    is_dst = insn.operands[0].type == 3
                    print(f"  {insn.address-base:#07x}  dst={is_dst}  {insn.mnemonic} {insn.op_str}")
    pos = i+1
