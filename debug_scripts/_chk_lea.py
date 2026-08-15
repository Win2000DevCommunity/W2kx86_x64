from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct
from x86x64.pe import PE32Image
from pathlib import Path
pe32=PE32Image(Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# scan 76d2..7cc3 for lea eax,[eax+eax+2] = 8d 44 40 02
for off in range(0x76d2-sec32.vaddr, 0x7cc3-sec32.vaddr):
    if td[off:off+4]==bytes([0x8d,0x44,0x40,0x02]):
        print(f"found at {sec32.vaddr+off:#x}")
        for insn in md32.disasm(td[off-0x20:off+0x30], pe32.image_base+sec32.vaddr+off-0x20):
            print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
