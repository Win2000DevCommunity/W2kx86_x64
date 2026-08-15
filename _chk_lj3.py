from pathlib import Path
from tools.audit_calls import read_text_section
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct

trva,data,_=read_text_section(Path("build_univ11/cmd_pure.exe").read_bytes())
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 0x1397c (returned 0, triggered longjmp path) ===")
for ins in md.disasm(data[0x1397c-trva:0x13a50-trva], 0x1397c, count=40):
    print(f"{ins.address:#07x}  {ins.bytes.hex():24s} {ins.mnemonic} {ins.op_str}")

# What is IAT 0x4ad011d4 / longjmp and setjmp
# Find setjmp usage - jmp_buf 0x4ad1fb40
print("\n=== search setjmp / fb40 refs in x86 ===")
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
# find push 0x4ad1fb40
needle=struct.pack("<I", 0x4ad1fb40)
pos=0
while True:
    i=src.find(needle, pos)
    if i<0: break
    print(f"  file {i:#x}")
    pos=i+1
