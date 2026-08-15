import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

x86 = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", x86, 0x3C)[0]
ns = struct.unpack_from("<H", x86, e+6)[0]
so = struct.unpack_from("<H", x86, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<I", x86, e+24+28)[0]
for i in range(ns):
    o = sec+i*40
    if x86[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", x86, o+8); break
xb = x86[rp:rp+rs]
md = Cs(CS_ARCH_X86, CS_MODE_32)

# disasm around each push 411
for site in [0x24ca, 0xc546, 0xc677, 0xc78c, 0xc7ec]:
    print(f"\n=== x86 {site:x} ===")
    off = site - 0x40 - va
    if off < 0: off = 0
    for insn in md.disasm(xb[site-va-0x30:site-va+0x50], site-0x30):
        print(f"  {insn.address:04x}: {insn.mnemonic} {insn.op_str}")
