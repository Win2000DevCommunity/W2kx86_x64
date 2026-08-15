# Simulate what _pure_mapped_entry_sane / find_sane would do for 0x195d2
import struct
from pathlib import Path
from tools.audit_calls import load_map, read_text_section

# Load x86 text
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break

x86=text[0x195d2-text_rva:0x195d2-text_rva+16]
print("x86 head", x86.hex())

trva,data,_=read_text_section(Path("build_univ3/cmd_pure.exe").read_bytes())
for off in (0x2fdc4, 0x2fdcc, 0x2fda7, 0x31e70, 0x31e75, 0x31e7d, 0x31e85):
    x64=data[off-trva:off-trva+16]
    print(hex(off), x64.hex())

# Check _looks_like_x64_insn_start and prologue for cmp rcx
from x86x64.translator._analysis import AnalysisMixin
print("prologue_ok 2fdcc", AnalysisMixin._x64_entry_prologue_ok(data, 0x2fdcc-trva))
print("bytes at 2fdcc", data[0x2fdcc-trva:0x2fdcc-trva+8].hex())

# How many calls SHOULD go to 0x195d2 from x86?
md_count=0
for i in range(len(text)-5):
    if text[i]!=0xe8: continue
    rel=struct.unpack_from("<i",text,i+1)[0]
    tgt=(text_rva+i+5+rel)&0xffffffff
    if tgt==0x195d2:
        md_count+=1
print("x86 calls to 0x195d2:", md_count)
