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
print("==== 3498d execute")
for insn in md.disasm(code[0x3498d-va:0x34a80-va], 0x80000000+0x3498d):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
    if insn.address > 0x80000000+0x34a40: break
# find calls to 1d7f4 from near 3498d region
for i in range(0x3498d-va, min(0x36000-va, len(code)-5)):
    if code[i]==0xE8:
        rel=struct.unpack_from("<i",code,i+1)[0]
        tgt=i+5+rel
        if tgt == 0x1d7f4-va:
            print("call 1d7f4 from", hex(va+i))
