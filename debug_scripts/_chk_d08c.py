from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
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
print("==== d08c ====")
for i, insn in enumerate(md.disasm(code[0xd08c-va:0xd08c-va+0x80], ib+0xd08c)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>40: break

pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("==== x86 70cf call into filler ====")
for i, insn in enumerate(md32.disasm(td[0x70ef-sec32.vaddr:0x70ef-sec32.vaddr+0x40], pe32.image_base+0x70ef)):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    if i>20: break
# find 14c39 
print("==== x86 14c39 ====")
for i, insn in enumerate(md32.disasm(td[0x14c39-sec32.vaddr:0x14c39-sec32.vaddr+0x40], pe32.image_base+0x14c39)):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    if i>20: break
