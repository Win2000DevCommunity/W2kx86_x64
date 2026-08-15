import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = bytearray(pathlib.Path("build_univ228/cmd_pure.exe").read_bytes())
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
for addr in [0x1d35c, 0x1d4f4, 0x1d534, 0x1d574, 0x1d5b4, 0x3624d]:
    print(f"=== {addr:x} ===")
    for insn in md.disasm(bytes(blob[addr-va:addr-va+50]), ib+addr):
        print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
        if insn.address-ib > addr+40: break
    print()
