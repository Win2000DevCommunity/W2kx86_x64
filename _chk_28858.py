from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ229/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
code = bytes(pe[rp:rp+rs])
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("==== 28858 (14c39) ====")
for i, insn in enumerate(md.disasm(code[0x28858-va:0x28858-va+0xc0], ib+0x28858)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>55: break
print("\n==== d08c more after length ====")
for i, insn in enumerate(md.disasm(code[0xd106-va:0xd106-va+0xc0], ib+0xd106)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>50: break
print("\n==== align stub pattern at c53e ====")
for i, insn in enumerate(md.disasm(code[0xc536-va:0xc536-va+0x30], ib+0xc536)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
