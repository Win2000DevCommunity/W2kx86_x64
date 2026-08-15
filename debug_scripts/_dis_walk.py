import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

pe = bytearray(pathlib.Path("build_univ227/cmd_univ4.exe").read_bytes())
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

print("=== pe64 early exit 1e5dd ===")
off = 0x1e5dd - va
for insn in md.disasm(bytes(blob[off:off+80]), ib+0x1e5dd):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    if insn.address-ib > 0x1e5dd+60: break

print("=== pe64 function containing 1e269 (find prologue) ===")
# scan back for common prologue
for start in range(0x1e100, 0x1e250, 1):
    pass
# disasm from 1e108 mentioned in jmp
off = 0x1e0d4 - va  # echo tip from summary
for insn in md.disasm(bytes(blob[off:off+120]), ib+0x1e0d4):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    if insn.address-ib > 0x1e0d4+100: break

# x86 early exit fd36 and the walker near fcxx for redirect
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
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 fd36 (iswspace fail) ===")
off = 0xfd36 - va2
for insn in md32.disasm(xb[off:off+40], 0xfd36):
    print(f"  {insn.address:04x}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0xfd36+30: break

print("=== x86 FB2B / walker with +0x14 ===")
# find lea/mov [eax+0x14] pattern near fb2b
off = 0xfb2b - va2
count=0
for insn in md32.disasm(xb[off:off+300], 0xfb2b):
    if '+0x14' in insn.op_str or '0x14' in insn.op_str or insn.address in (0xfb2b,0xfba0,0xfbc0,0xfbe0):
        print(f"  {insn.address:04x}: {insn.mnemonic} {insn.op_str}")
    count+=1
    if insn.address >= 0xfbe4: break
# specifically find call fbe4 and following
print("--- call FBE4 sites in fbxx ---")
off = 0xfb00 - va2
for insn in md32.disasm(xb[off:off+400], 0xfb00):
    if insn.mnemonic=='call' and '0xfbe4' in insn.op_str:
        print(f"  {insn.address:04x}: {insn.mnemonic} {insn.op_str}")
    if '0x14' in insn.op_str and insn.mnemonic in ('mov','lea'):
        print(f"  {insn.address:04x}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0xfc00: break
