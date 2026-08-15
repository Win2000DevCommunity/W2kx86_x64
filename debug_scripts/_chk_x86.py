# Find x86 target of calls near 0xa4e7 that should hit XcptFilter stub
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from tools.audit_calls import load_map, read_text_section

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
# parse pe32 text
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]
soh = struct.unpack_from("<H", src, e+20)[0]
sec = e+24+soh
text_rva=text_raw=text_sz=0
for i in range(num):
    o=sec+i*40
    name=src[o:o+8].split(b"\0")[0]
    vs,va,rs,rp=struct.unpack_from("<IIII", src, o+8)
    if name==b".text":
        text_rva,text_raw,text_sz=va,rp,rs
        break
text=src[text_raw:text_raw+text_sz]
base=struct.unpack_from("<I", src, e+24+28)[0]
print("x86 base", hex(base), "text_rva", hex(text_rva))

rmap=load_map(Path("build_univ3/rva.txt"))
md=Cs(CS_ARCH_X86, CS_MODE_32)
md.detail=True

# Disassemble x86 function at 0xa4e7
fn=0xa4e7
print("=== x86 @", hex(fn), "===")
for insn in md.disasm(text[fn-text_rva:fn-text_rva+0x200], base+fn, count=80):
    mark=""
    if insn.mnemonic=="call" and insn.operands and insn.operands[0].type==2: # IMM
        tgt=(insn.operands[0].imm-base)&0xffffffff
        x64=rmap.get(tgt)
        mark=f"  -> x86 {hex(tgt)} x64map={hex(x64) if x64 is not None else None}"
    print(f"{insn.address-base:#07x}  {insn.bytes.hex():20s} {insn.mnemonic} {insn.op_str}{mark}")
    if insn.address-base > fn+0x180:
        break
