from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct
from x86x64.pe import PE32Image
from pathlib import Path
pe32=PE32Image(Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section(); md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("==== x86 mov eax,imm near end of 76d2 ====")
for insn in md32.disasm(td[0x76d2-sec32.vaddr:0x7cca-sec32.vaddr], pe32.image_base+0x76d2):
    if insn.mnemonic=="mov" and insn.op_str.startswith("eax,") and any(c.isdigit() for c in insn.op_str):
        if "ebp" not in insn.op_str and "dword" not in insn.op_str:
            print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic in ("xor",) and "eax, eax" in insn.op_str:
        print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
# pe64 d08c return paths
pe=bytearray(Path("build_univ230/cmd_fix3.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
print("\n==== pe64 d08c rets / mov eax ====")
for insn in md.disasm(code[0xd08c-va:0xdeaa-va], ib+0xd08c):
    if insn.mnemonic=="ret":
        print(f"  {insn.address:#x}: ret")
    if insn.mnemonic=="mov" and ("eax, 1" in insn.op_str or "eax, 2" in insn.op_str or "rax, 1" in insn.op_str or "rax, 2" in insn.op_str or "eax, 5" in insn.op_str):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
