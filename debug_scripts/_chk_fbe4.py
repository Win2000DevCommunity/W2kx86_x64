from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct, pathlib
from x86x64.pe import PE32Image

pe = bytearray(pathlib.Path("build_univ228/cmd_combo.exe").read_bytes())
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
print("==== fbe4 pe64 1e2b4 ====")
for i, insn in enumerate(md.disasm(code[0x1e2b4-va:0x1e2b4-va+0x120], ib+0x1e2b4)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>55: break

pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("==== x86 fbe4 ====")
for i, insn in enumerate(md32.disasm(td[0xfbe4-sec32.vaddr:0xfbe4-sec32.vaddr+0xa0], pe32.image_base+0xfbe4)):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    if i>40: break
