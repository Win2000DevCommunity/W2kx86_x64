from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct, pathlib
from x86x64.pe import PE32Image
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
target_va=pe32.image_base+0x1c628
imm=struct.pack("<I", target_va)
print("looking for", hex(target_va))
off=0
while True:
    j=td.find(imm, off)
    if j<0: break
    print(f"\nimm at rva={sec32.vaddr+j:#x}")
    # walk back to push ebp
    start=j
    for b in range(j, max(0,j-0x100), -1):
        if td[b]==0x55 and b+2<len(td) and td[b+1]==0x8b and td[b+2]==0xec:
            start=b; break
    print(f"fn start rva={sec32.vaddr+start:#x}")
    for insn in md32.disasm(td[start:start+0x60], pe32.image_base+sec32.vaddr+start):
        print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    # epi
    for i in range(start, min(len(td)-1, start+0x600)):
        if td[i]==0xc9 and td[i+1]==0xc3:
            print("leave;ret at", hex(sec32.vaddr+i))
            for insn in md32.disasm(td[i-15:i+2], pe32.image_base+sec32.vaddr+i-15):
                print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
            break
    off=j+1
