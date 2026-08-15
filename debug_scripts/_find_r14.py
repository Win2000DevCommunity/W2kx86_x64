import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = bytearray(pathlib.Path("build_univ227/cmd_univ9.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = pe[rp:rp+rs]
md = Cs(CS_ARCH_X86, CS_MODE_64)

# find function start - look for push rbp before 17b00
print("=== full 17900..17d80 looking for r14 ===")
for insn in md.disasm(bytes(blob[0x17900-va:0x17900-va+0x500]), ib+0x17900):
    s = f"{insn.mnemonic} {insn.op_str}"
    if "r14" in s or insn.address-ib in (0x17900,0x17a00,0x17b00,0x17c00,0x17d00):
        print(f"  {insn.address-ib:05x}: {s}")

# Resolve IAT 0x4ad011a8 from x86 - what import?
# read pe64 imports for SetThreadLocale
import re
# find movabs loading something then into r14
print("\n=== any mov r14 in 0x16000-0x18000 ===")
for insn in md.disasm(bytes(blob[0x16000-va:0x18000-va]), ib+0x16000):
    if insn.mnemonic.startswith("mov") and "r14" in insn.op_str:
        print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
