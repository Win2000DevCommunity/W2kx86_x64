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
print("==== 1d951+ ====")
for i, insn in enumerate(md.disasm(code[0x1d951-va:0x1d951-va+0x80], ib+0x1d951)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>30: break
print("==== 3628d ====")
for i, insn in enumerate(md.disasm(code[0x3628d-va:0x3628d-va+0x60], ib+0x3628d)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>25: break

pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("==== x86 fb2b ====")
for i, insn in enumerate(md32.disasm(td[0xfb2b-sec32.vaddr:0xfb2b-sec32.vaddr+0x80], pe32.image_base+0xfb2b)):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    if i>35: break
print("==== x86 f79b/f794 ====")
for addr in [0xf78d,0xf794,0xf79b,0xf7a2]:
    print(f"-- {addr:#x}")
    for i, insn in enumerate(md32.disasm(td[addr-sec32.vaddr:addr-sec32.vaddr+0x30], pe32.image_base+addr)):
        print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
        if i>12: break
