from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ227/cmd_echo2.exe").read_bytes())
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
print("==== 386ac")
for insn in md.disasm(code[0x386a0-va:0x386e0-va], 0x80000000+0x386a0):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
print("==== 386cc")
for insn in md.disasm(code[0x386c0-va:0x386f0-va], 0x80000000+0x386c0):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
# raw bytes at 19f70
print("19f70", code[0x19f70-va:0x19f95-va].hex())
