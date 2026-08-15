from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from x86x64.pe import PE32Image
from pathlib import Path
pe32=PE32Image(Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section(); md32=Cs(CS_ARCH_X86,CS_MODE_32)
for insn in md32.disasm(td[0x76d2-sec32.vaddr:0x7cca-sec32.vaddr], pe32.image_base+0x76d2):
    s=insn.op_str
    if insn.mnemonic=="mov" and (s=="eax, 1" or s=="eax, 2" or s=="eax, 5" or s.startswith("eax, 0x")):
        print(f"  {insn.address:08x}: {insn.mnemonic} {s}")
    if insn.mnemonic=="push" and s in ("1","2","5"):
        print(f"  {insn.address:08x}: {insn.mnemonic} {s}")
# search for pop eax or mov eax,[ebp-4] before ret
print("--- near 7b80-7cc9 ---")
for insn in md32.disasm(td[0x7b80-sec32.vaddr:0x7cc9-sec32.vaddr], pe32.image_base+0x7b80):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
