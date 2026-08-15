from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct, pathlib
from x86x64.pe import PE32Image

# what is 19f94
pe=bytearray(pathlib.Path("build_univ230/cmd_fix2.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
print("==== 19f94 ====")
for i, insn in enumerate(md.disasm(code[0x19f94-va:0x19f94-va+0x40], ib+0x19f94)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>20: break

# x86 76d2 path around realloc - search for lea eax,[eax+eax+2]
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# in 76d2 function find pattern
print("\n==== x86 near 7a00 ====")
for insn in md32.disasm(td[0x79e0-sec32.vaddr:0x79e0-sec32.vaddr+0x80], pe32.image_base+0x79e0):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
