from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from x86x64.pe import PE32Image
from pathlib import Path
pe32=PE32Image(Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
for insn in md32.disasm(td[0x76d2-sec32.vaddr:0x7cc3-sec32.vaddr], pe32.image_base+0x76d2):
    if "eax + eax" in insn.op_str or "* 2" in insn.op_str or "eax*2" in insn.op_str.replace(" ",""):
        print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
# also show around push after strlen path - search call db95 or realloc
print("--- calls near 7b00 ---")
for insn in md32.disasm(td[0x7ae0-sec32.vaddr:0x7ae0-sec32.vaddr+0xa0], pe32.image_base+0x7ae0):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
