from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ227/cmd_univ2.exe").read_bytes())
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
print("==== 1e150-1e280")
for insn in md.disasm(code[0x1e150-va:0x1e280-va], 0x80000000+0x1e150):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))

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
print("==== x86 fb5d-fbd0")
for insn in md32.disasm(xt[0xfb5d-tr:0xfbd0-tr], ib+0xfb5d):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
