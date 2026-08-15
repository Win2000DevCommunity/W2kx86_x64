from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ225/cmd_f4eb.exe").read_bytes())
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
print("==== F4EB pe64")
for insn in md.disasm(code[0x1d35c-va:0x1d4c0-va], 0x80000000+0x1d35c):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
print("==== 262D3")
for insn in md.disasm(code[0x262c0-va:0x26320-va], 0x80000000+0x262c0):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
