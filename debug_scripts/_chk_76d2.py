from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from x86x64.pe import PE32Image
import pathlib
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("==== x86 76d2 ====")
for i, insn in enumerate(md32.disasm(td[0x76d2-sec32.vaddr:0x76d2-sec32.vaddr+0xa0], pe32.image_base+0x76d2)):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    if i>50: break
print("==== x86 14c39 more ====")
for i, insn in enumerate(md32.disasm(td[0x14c39-sec32.vaddr:0x14c39-sec32.vaddr+0x80], pe32.image_base+0x14c39)):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    if i>40: break
