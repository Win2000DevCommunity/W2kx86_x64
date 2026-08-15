import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import sys
sys.path.insert(0,'.')
from x86x64.translator._analysis import AnalysisMixin

data=Path("build_univ20/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=bytearray(data[rp:rp+rs]); text_rva=va; break

# rva_map dump is PE RVA - convert
rmap={}
for line in Path("build_univ20/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b-text_rva if b>=text_rva else b

off=rmap[0x27b2]
print("27b2 blob off", hex(off), "bytes", text[off:off+16].hex())
print("prologue_ok", AnalysisMixin._x64_entry_prologue_ok(text, off))
print("at +8", hex(off+8), text[off+8:off+16].hex(), "ok", AnalysisMixin._x64_entry_prologue_ok(text, off+8))

# Find push rbx near
for d in range(0, 32):
    if text[off+d]==0x53:
        print(f"push rbx at +{d} off {off+d:#x} ok={AnalysisMixin._x64_entry_prologue_ok(text, off+d)}")
