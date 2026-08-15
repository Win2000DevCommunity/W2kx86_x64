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
print("\n=== pe64 find r14 setup before 17d62 ===")
for insn in md.disasm(bytes(blob[0x17a80-va:0x17a80-va+0x300]), ib+0x17a80):
    if "r14" in insn.op_str or insn.address-ib in range(0x17d20,0x17d80):
        print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
