from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct, pathlib
from x86x64.pe import PE32Image

# pe64 body
pe = bytearray(pathlib.Path("build_univ228/cmd_pure.exe").read_bytes())
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
print("==== pe64 1d5b4 body (80 insn) ====")
for i, insn in enumerate(md.disasm(code[0x1d5b4-va:0x1d5b4-va+0x120], 0x80000000+0x1d5b4)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i > 60: break

print("==== pe64 helper continue 3988e ====")
for i, insn in enumerate(md.disasm(code[0x3988e-va:0x3988e-va+0x80], 0x80000000+0x3988e)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i > 40: break

# x86 f5ed
SRC=pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
pe32=PE32Image(SRC.read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("==== x86 f5ed ====")
for i, insn in enumerate(md32.disasm(td[0xf5ed-sec32.vaddr:0xf5ed-sec32.vaddr+0x80], pe32.image_base+0xf5ed)):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    if i > 40: break
