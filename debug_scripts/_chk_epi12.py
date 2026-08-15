from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct, pathlib
from x86x64.pe import PE32Image
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("==== x86 131c0-13200 ====")
for insn in md32.disasm(td[0x131c0-sec32.vaddr:0x131c0-sec32.vaddr+0x50], pe32.image_base+0x131c0):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
print("==== pe64 24e00 ====")
from capstone import CS_MODE_64
pe = bytearray(pathlib.Path("build_univ229/cmd_diam.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]; so=struct.unpack_from("<H", pe, e+20)[0]; sec=e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
for insn in md.disasm(code[0x24df0-va:0x24e20-va], ib+0x24df0):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
