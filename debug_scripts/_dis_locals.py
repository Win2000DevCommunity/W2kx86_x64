import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

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

print("=== 1e2b4 (zero-quad tip) through homes ===")
for insn in md.disasm(bytes(blob[0x1e2b4-va:0x1e2b4-va+30]), ib+0x1e2b4):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")

print("=== 47510 ===")
for insn in md.disasm(bytes(blob[0x47510-va:0x47510-va+40]), ib+0x47510):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic=='ret': break

print("=== search fbe4 local inc [rsp+10] equivalents ===")
# in x86 fc59: inc dword [esp+0x10]
# scan 1e2c0..1e620 for inc dword
for insn in md.disasm(bytes(blob[0x1e2c0-va:0x1e620-va]), ib+0x1e2c0):
    if 'inc' in insn.mnemonic or ('rsp' in insn.op_str and ('0x10' in insn.op_str or '0x14' in insn.op_str or '+ 0x10' in insn.op_str)):
        if insn.mnemonic.startswith('inc') or 'dword' in insn.op_str or 'cmp' in insn.mnemonic or 'mov' in insn.mnemonic:
            if any(x in insn.op_str for x in ('0x10','0x14','0x48','0x50')) or insn.mnemonic=='inc':
                print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")

# BP approach: patch early exit to always return 0 and see if echo works
print("\n=== pe64 around 1e370 (store to [rdi]) and return paths ===")
for insn in md.disasm(bytes(blob[0x1e370-va:0x1e370-va+200]), ib+0x1e370):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    if insn.address-ib > 0x1e420: break
