from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from x86x64.pe import PE32Image
from pathlib import Path
pe32=PE32Image(Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section(); md32=Cs(CS_ARCH_X86,CS_MODE_32)
for insn in md32.disasm(td[0x7cf0-sec32.vaddr:0x7d40-sec32.vaddr], pe32.image_base+0x7cf0):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
# also 7a1a loop - what does it return eventually for simple "echo w2ktest"
print("\n==== 7a1a ====")
for insn in md32.disasm(td[0x7a1a-sec32.vaddr:0x7a1a-sec32.vaddr+0x40], pe32.image_base+0x7a1a):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
