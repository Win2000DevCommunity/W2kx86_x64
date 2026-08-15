import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
for name in ["cmd_pure.exe", "cmd_univ12.exe"]:
    pe = bytearray(pathlib.Path(f"build_univ227/{name}").read_bytes())
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
    print(name, "d538", blob[0xd538-va:0xd560-va].hex())
    md=Cs(CS_ARCH_X86, CS_MODE_64)
    for insn in md.disasm(bytes(blob[0xd520-va:0xd520-va+0x50]), ib+0xd520):
        print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    print()
