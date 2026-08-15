from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ229/cmd_diam.exe").read_bytes())
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
print("==== around 32020 ====")
for insn in md.disasm(code[0x31ff0-va:0x31ff0-va+0x80], ib+0x31ff0):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
print("==== d08c from d1ab aligned ====")
for i, insn in enumerate(md.disasm(code[0xd1ab-va:0xd1ab-va+0x150], ib+0xd1ab)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>60: break
print("==== 27df8 ====")
for i, insn in enumerate(md.disasm(code[0x27df8-va:0x27df8-va+0x40], ib+0x27df8)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
