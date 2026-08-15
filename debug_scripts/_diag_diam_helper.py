import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

pe = bytearray(pathlib.Path("build_univ228/cmd_diam8.exe").read_bytes())
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

# Diamond helper called from 3627f -> 1e62c -> jmp 3988e
print("=== 3988e diamond helper ===")
for insn in md.disasm(bytes(blob[0x3988e-va:0x3988e-va+0x120]), ib+0x3988e):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    if insn.address-ib > 0x39950: break

print("\n=== 1e62c entry ===")
for insn in md.disasm(bytes(blob[0x1e62c-va:0x1e62c-va+0x30]), ib+0x1e62c):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")

# x86 FD5D shared helper
x86 = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e2 = struct.unpack_from("<I", x86, 0x3C)[0]
ns2 = struct.unpack_from("<H", x86, e2+6)[0]
so2 = struct.unpack_from("<H", x86, e2+20)[0]
sec2 = e2+24+so2
for i in range(ns2):
    o = sec2+i*40
    if x86[o:o+5]==b".text":
        vs2,va2,rs2,rp2=struct.unpack_from("<IIII", x86, o+8); break
xb=x86[rp2:rp2+rs2]
md32=Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 FD5D ===")
off=0xfd5d-va2
for insn in md32.disasm(xb[off:off+0x80], 0xfd5d):
    print(f"  {insn.address:04x}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0xfd5d+0x70: break
