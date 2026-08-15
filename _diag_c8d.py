import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_OP_IMM

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

# Known load at 0xf06e: 8b 0d d8 c8 d1 4a
off = 0xf06e - text_rva
print("bytes", text[off:off+6].hex())
for insn in md.disasm(text[off:off+6], base+0xf06e, count=1):
    print(insn.mnemonic, insn.op_str)
    for op in insn.operands:
        print("  type", op.type, "imm", getattr(op, "imm", None),
              "mem.disp", op.mem.disp if op.type == X86_OP_MEM else None,
              "mem.base", op.mem.base if op.type == X86_OP_MEM else None)

# Search ALL mov-to-mem with abs form in .data range
print("\nAbsolute stores into .data range 0x4ad1c000-0x4ad29400:")
count = 0
for insn in md.disasm(text, base+text_rva):
    if insn.mnemonic != "mov" or len(insn.operands) < 2:
        continue
    op0 = insn.operands[0]
    if op0.type != X86_OP_MEM:
        continue
    if op0.mem.base != 0 or op0.mem.index != 0:
        continue
    d = op0.mem.disp & 0xFFFFFFFF
    if 0x4ad1c000 <= d < 0x4ad29400:
        print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
        count += 1
        if count >= 40:
            break
print("shown", count)

# Specifically search encoding 89 05 / C7 05 in data range by scanning
print("\nEncoded abs stores (89/c7 05) targeting data:")
i = 0
found = 0
while i < len(text)-6:
    if text[i:i+2] in (b"\x89\x05", b"\xc7\x05", b"\x89\x0d", b"\x89\x15",
                        b"\x89\x1d", b"\x89\x35", b"\x89\x3d", b"\xa3"):
        if text[i] == 0xa3:
            addr = struct.unpack_from("<I", text, i+1)[0]
            plen = 5
        else:
            addr = struct.unpack_from("<I", text, i+2)[0]
            plen = 6 if text[i] != 0xc7 else 10
        if 0x4ad1c000 <= addr < 0x4ad29400:
            print(f"  {text_rva+i:#07x}  op={text[i:i+2].hex()} addr={addr:#x}")
            found += 1
            if found > 30:
                break
        i += 1
    else:
        i += 1
print("found", found)
