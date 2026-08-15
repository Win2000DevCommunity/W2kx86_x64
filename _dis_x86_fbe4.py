import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86 = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", x86, 0x3C)[0]
ns = struct.unpack_from("<H", x86, e+6)[0]
so = struct.unpack_from("<H", x86, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if x86[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", x86, o+8); break
blob = x86[rp:rp+rs]
md = Cs(CS_ARCH_X86, CS_MODE_32)
# FBE4 tip
print("=== x86 FBE4 ===")
off = 0xFBE4 - va
for insn in md.disasm(blob[off:off+200], 0xFBE4):
    print(f"  {insn.address:04x}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0xFBE4+180: break
