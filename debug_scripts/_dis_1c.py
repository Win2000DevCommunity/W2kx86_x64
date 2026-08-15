import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = bytearray(pathlib.Path("build_univ228/cmd_diam5.exe").read_bytes())
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
for addr in [0x1c520, 0x1c53e, 0x1c570, 0x1c57e, 0x1c5b4]:
    print(f"=== {addr:x} ===")
    for insn in md.disasm(bytes(blob[addr-va:addr-va+40]), ib+addr):
        print(f"  {insn.address-ib:05x}: {insn.bytes.hex():20s} {insn.mnemonic} {insn.op_str}")
        if insn.address-ib>addr+30: break
