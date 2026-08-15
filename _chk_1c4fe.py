from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ225/cmd_both.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
code = bytes(pe[rp:rp+rs])
md = Cs(CS_ARCH_X86, CS_MODE_64)
for start in (0x1c4fe, 0x1c35c, 0x1c53e, 0x48bea):
    print("====", hex(start))
    for insn in md.disasm(code[start-va:start-va+48], 0x80000000+start):
        print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
# also check diamond code-arg heal - what should r8/r9 be
# x86 f5a8 and f4eb
print("x86 f5a8/f4eb should map to pe64")
