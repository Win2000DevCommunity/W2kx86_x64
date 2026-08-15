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
# disasm 24b40-24d50 and find what loads rcx before those calls
for label,rva,n in [("24b40",0x24b40,0x50),("24d00",0x24d00,0x50),("d7a0",0xd7a0,0x60)]:
    print(f"\n==== {label} ====")
    for insn in md.disasm(code[rva-va:rva-va+n], ib+rva):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# x86 source for this fn - find via ret site d7d6
print("\n==== callers of pattern / x86 ====")
from x86x64.pe import PE32Image
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
# map pe64 249e8 roughly - use string 0x80058628 -> data
