import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from tools.audit_calls import load_map, read_text_section
from x86x64.translator._analysis import AnalysisMixin

rmap=load_map(Path("build_univ3/rva.txt"))
blob=Path("build_univ3/cmd_pure.exe").read_bytes()
trva,data,_=read_text_section(blob)
md=Cs(CS_ARCH_X86, CS_MODE_64)

print("0x1a770 ->", hex(rmap.get(0x1a770)))
print("0x195d2 ->", hex(rmap.get(0x195d2)))
print("prologue 0x31e75", AnalysisMixin._x64_entry_prologue_ok(data, 0x31e75-trva))
print("prologue 0x2fdc4", AnalysisMixin._x64_entry_prologue_ok(data, 0x2fdc4-trva))

print("\n=== x64 @ 0x2fdc4 ===")
for ins in md.disasm(data[0x2fdc4-trva:0x2fdc4-trva+40], 0x2fdc4):
    print(hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str)

# x86 at 0x1a770 - is it chkstk?
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break
base=struct.unpack_from("<I",src,e+24+28)[0]
md32=Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 @ 0x1a770 ===")
for insn in md32.disasm(text[0x1a770-text_rva:0x1a770-text_rva+40], base+0x1a770, count=15):
    print(hex(insn.address-base), insn.bytes.hex(), insn.mnemonic, insn.op_str)

print("\n=== x86 @ 0x195d2 ===")
for insn in md32.disasm(text[0x195d2-text_rva:0x195d2-text_rva+40], base+0x195d2, count=15):
    print(hex(insn.address-base), insn.bytes.hex(), insn.mnemonic, insn.op_str)

# How many E8s target 0x31e85 vs 0x2fdc4?
import struct as st
c31=c2f=0
for i in range(len(data)-5):
    if data[i]!=0xE8: continue
    t=(trva+i+5+st.unpack_from("<i",data,i+1)[0])&0xffffffff
    if t==0x31e85: c31+=1
    if t==0x2fdc4: c2f+=1
print("calls to 0x31e85", c31, "to 0x2fdc4", c2f)

# Is 0x31e85 = refine(0x31e75)?
print("\n0x31e75 region:")
for ins in md.disasm(data[0x31e70-trva:0x31e98-trva], 0x31e70):
    print(hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str)
