from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct, pathlib

pe = bytearray(pathlib.Path("build_univ227/cmd_fbe4.exe").read_bytes())
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
print("==== 19d80-19e20")
for insn in md.disasm(code[0x19d80-va:0x19e40-va], 0x80000000+0x19d80):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
print("==== 1d7f4 echo")
for insn in md.disasm(code[0x1d7f4-va:0x1d880-va], 0x80000000+0x1d7f4):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
print("==== 1eb80-1ebc0")
for insn in md.disasm(code[0x1eb80-va:0x1ebc0-va], 0x80000000+0x1eb80):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))

# x86 echodisp after lstrcmp success - WriteConsole path
x86 = bytearray(pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
e = struct.unpack_from("<I", x86, 0x3C)[0]
ns = struct.unpack_from("<H", x86, e+6)[0]
so = struct.unpack_from("<H", x86, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<I", x86, e+24+28)[0]
for i in range(ns):
    o = sec+i*40
    if x86[o:o+5] == b".text":
        vs,va32,rs,rp = struct.unpack_from("<IIII", x86, o+8)
        xt = bytes(x86[rp:rp+rs]); tr = va32; break
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("==== x86 f6fd echo body")
for insn in md32.disasm(xt[0xf6fd-tr:0xf7b0-tr], ib+0xf6fd):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
