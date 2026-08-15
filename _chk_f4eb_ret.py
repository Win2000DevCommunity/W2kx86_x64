from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct, pathlib
x86 = bytearray(pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
e = struct.unpack_from("<I", x86, 0x3C)[0]
ns = struct.unpack_from("<H", x86, e+6)[0]
so = struct.unpack_from("<H", x86, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<I", x86, e+24+28)[0]
for i in range(ns):
    o = sec+i*40
    if x86[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", x86, o+8)
        text = bytes(x86[rp:rp+rs]); tr = va; break
md = Cs(CS_ARCH_X86, CS_MODE_32)
print("==== rest of F4EB to ret")
for insn in md.disasm(text[0xf53c-tr:0xf5e0-tr], ib+0xf53c):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
    if insn.mnemonic.startswith("ret"):
        break

# pe64 F4EB end
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
md64 = Cs(CS_ARCH_X86, CS_MODE_64)
print("==== pe64 F4EB cont 1d4b0+")
for insn in md64.disasm(code[0x1d4b0-va:0x1d560-va], 0x80000000+0x1d4b0):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
