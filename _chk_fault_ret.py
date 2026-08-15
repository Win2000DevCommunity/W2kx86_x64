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
# disasm around fault return 0x80032020 and 0x80024ab4
for label,rva,n in [("32000",0x31f00,0x200),("24ab4",0x24a80,0x80),("d08c_more",0xd1c0,0x120)]:
    print(f"\n==== {label} ====")
    off=rva-va
    for i, insn in enumerate(md.disasm(code[off:off+n], ib+rva)):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if i>45: break
