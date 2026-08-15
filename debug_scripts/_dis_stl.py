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
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", pe, o+8); break
blob=pe[rp:rp+rs]
md=Cs(CS_ARCH_X86, CS_MODE_64)

# disasm function containing 17d62 - find prologue walking back
for start in range(0x17c71, 0x17800, -1):
    pass
print("=== 17680..177b0 ===")
for insn in md.disasm(bytes(blob[0x17680-va:0x17680-va+0x150]), ib+0x17680):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")

print("\n=== 17a20..17ab0 ===")
for insn in md.disasm(bytes(blob[0x17a00-va:0x17a00-va+0xc0]), ib+0x17a00):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
