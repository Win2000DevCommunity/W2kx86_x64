import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]
soh = struct.unpack_from("<H", src, e+20)[0]
sec = e+24+soh
for i in range(num):
    o = sec+i*40
    if src[o:o+5] == b".text":
        va, rs, rp = struct.unpack_from("<III", src, o+12)
        text = src[rp:rp+rs]; text_rva = va; break
base = struct.unpack_from("<I", src, e+24+28)[0]
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
needle = struct.pack("<I", 0x4ad1c8d8)
print("STORE-like refs to c8d8:")
pos = 0
while True:
    i = text.find(needle, pos)
    if i < 0: break
    start = max(0, i-8)
    for insn in md.disasm(text[start:i+6], base+text_rva+start, count=5):
        if needle in insn.bytes and insn.mnemonic.startswith("mov") and "c8d8" in insn.op_str.replace("0x4ad1",""):
            pass
        if insn.mnemonic in ("mov", "and", "or", "xor", "xchg") and needle in insn.bytes:
            # mem dest?
            if "[" in insn.op_str and insn.op_str.find("[") < insn.op_str.find(","):
                print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
    pos = i+1
