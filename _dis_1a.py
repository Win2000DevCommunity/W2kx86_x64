import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = bytearray(pathlib.Path("build_univ227/cmd_univ12.exe").read_bytes())
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
print("=== 19fc0..1a040 ===")
for insn in md.disasm(bytes(blob[0x19fc0-va:0x19fc0-va+0x80]), ib+0x19fc0):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
print("=== d560 ===")
for insn in md.disasm(bytes(blob[0xd540-va:0xd540-va+0x60]), ib+0xd540):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
