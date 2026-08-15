import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = bytearray(pathlib.Path("build_univ227/cmd_univ8.exe").read_bytes())
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

print("=== around 17d40 ===")
for insn in md.disasm(bytes(blob[0x17d40-va:0x17d40-va+80]), ib+0x17d40):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    if insn.address-ib > 0x17da0: break

print("=== around 17c90 ===")
for insn in md.disasm(bytes(blob[0x17c90-va:0x17c90-va+100]), ib+0x17c90):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    if insn.address-ib > 0x17d20: break

# x86 equivalent - find by looking at cmd for similar
