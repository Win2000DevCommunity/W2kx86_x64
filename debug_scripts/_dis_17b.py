import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

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

print("=== 17b00..17d80 ===")
for insn in md.disasm(bytes(blob[0x17b00-va:0x17b00-va+0x280]), ib+0x17b00):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")

# find x86 with push 0x411 pattern
x86 = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e2 = struct.unpack_from("<I", x86, 0x3C)[0]
ns2 = struct.unpack_from("<H", x86, e2+6)[0]
so2 = struct.unpack_from("<H", x86, e2+20)[0]
sec2 = e2+24+so2
for i in range(ns2):
    o = sec2+i*40
    if x86[o:o+5] == b".text":
        vs2,va2,rs2,rp2 = struct.unpack_from("<IIII", x86, o+8); break
xb = x86[rp2:rp2+rs2]
# 68 11 04 00 00 = push 0x411
idx = 0
while True:
    j = xb.find(bytes.fromhex("6811040000"), idx)
    if j < 0: break
    print("x86 push 411 at", hex(va2+j))
    idx = j+1
