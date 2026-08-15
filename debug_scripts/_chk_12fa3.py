from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct, pathlib
from x86x64.pe import PE32Image
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
print("==== pe64 249e8 early ====")
for insn in md.disasm(code[0x249e8-va:0x249e8-va+0x50], ib+0x249e8):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
print("\n==== pe64 early exit 24e12 area and 24a0d ====")
for insn in md.disasm(code[0x24a0d-va:0x24a0d-va+0x20], ib+0x24a0d):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("\n==== x86 12fa3 full prologue+epi ====")
for insn in md32.disasm(td[0x12fa3-sec32.vaddr:0x12fa3-sec32.vaddr+0x50], pe32.image_base+0x12fa3):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
print("--- epi ---")
for insn in md32.disasm(td[0x131d0-sec32.vaddr:0x131d0-sec32.vaddr+0x30], pe32.image_base+0x131d0):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
