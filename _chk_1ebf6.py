from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
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
print("==== 1eba0-1ec40")
for insn in md.disasm(code[0x1eba0-va:0x1ec50-va], 0x80000000+0x1eba0):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
print("==== 1d7f4 continue after lstrcmp")
for insn in md.disasm(code[0x1d879-va:0x1d960-va], 0x80000000+0x1d879):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
print("==== 1d900-1d980")
for insn in md.disasm(code[0x1d900-va:0x1d980-va], 0x80000000+0x1d900):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))

# x86 fb2b - called when all lstrcmp fail in echo (default path)
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
print("==== x86 fb2b (echo default print?)")
for insn in md32.disasm(xt[0xfb2b-tr:0xfb80-tr], ib+0xfb2b):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
