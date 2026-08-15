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
# find rets in function - scan for pop rsi; pop rbp; ret patterns from 249e8
print("==== epilogues / pops in 249e8..24e80 ====")
for insn in md.disasm(code[0x249e8-va:0x24e80-va], ib+0x249e8):
    if insn.mnemonic in ("ret","pop","leave") or "rsi" in insn.op_str and insn.mnemonic=="pop":
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# also show end of function around 24e00
print("\n==== 24de0 ====")
for insn in md.disasm(code[0x24de0-va:0x24e40-va], ib+0x24de0):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
