import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = bytearray(pathlib.Path("build_univ227/cmd_univ6.exe").read_bytes())
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

print("=== early exit region ===")
for insn in md.disasm(bytes(blob[0x1e5d0-va:0x1e5d0-va+120]), ib+0x1e5d0):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    if insn.address-ib > 0x1e640: break

# find all e9 from 1e2b4..1e650 and their targets
print("=== rel32 branches in fbe4 ===")
for j in range(0x1e2b4-va, 0x1e650-va):
    if blob[j] == 0xE9:
        rel = struct.unpack_from("<i", blob, j+1)[0]
        tgt = j+5+rel
        print(f"  {va+j:05x} -> {va+tgt:05x} bytes {blob[tgt:tgt+8].hex()}")

# also 0f 84/85 etc
for j in range(0x1e2b4-va, 0x1e650-va-5):
    if blob[j]==0x0f and blob[j+1] in (0x84,0x85,0x8c,0x8d,0x8e,0x8f,0x88,0x89,0x8a,0x8b):
        rel = struct.unpack_from("<i", blob, j+2)[0]
        tgt = j+6+rel
        if abs(tgt - (0x47510-va)) < 5 or (0 <= tgt < len(blob) and blob[tgt:tgt+5]==bytes.fromhex("5f5e5d5bc3")):
            print(f"  jcc {va+j:05x} -> {va+tgt:05x}")
