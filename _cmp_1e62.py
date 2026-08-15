import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
for name in ["build_univ227/cmd_univ12.exe", "build_univ228/cmd_pure.exe"]:
    pe = bytearray(pathlib.Path(name).read_bytes())
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
    print("===", name, "1e5f0..1e660 ===")
    for insn in md.disasm(bytes(blob[0x1e5f0-va:0x1e5f0-va+0x80]), ib+0x1e5f0):
        print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    print("bytes 1e620", blob[0x1e620-va:0x1e630-va].hex())
    print()
