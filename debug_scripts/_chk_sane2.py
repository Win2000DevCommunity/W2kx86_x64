# Simulate find_sane / mapped_entry_sane against univ3 blob without full translator
import struct
from pathlib import Path
from tools.audit_calls import load_map, read_text_section

# Minimal: just test the cmp rule and forward scan
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break

trva,data,_=read_text_section(Path("build_univ3/cmd_pure.exe").read_bytes())
data=bytearray(data)
rmap=load_map(Path("build_univ3/rva.txt"))

x86=text[0x195d2-text_rva:0x195d2-text_rva+16]
print("x86", x86.hex(), "imm", x86[4])

def sane(off):
    x64=bytes(data[off:off+16])
    if x86[:4]==b"\x83\x7c\x24\x04":
        ib=x86[4]
        ok=(x64[:4]==bytes((0x48,0x83,0xf9,ib)) or x64[:3]==bytes((0x83,0xf9,ib)))
        return ok
    return False

base=rmap[0x195d2]
print("base", hex(base), "sane?", sane(base-trva))
for d in range(0,12):
    cand=base-trva+d
    print(f"  d={d} off={hex(cand+trva)} sane={sane(cand)} bytes={bytes(data[cand:cand+4]).hex()}")

# Why would calls end at 0x31e85? Check if 0x2fdcc has callers after a dry-run patch
# Count calls that SHOULD be to 195d2 by looking at align stubs before call
# and seeing if we can match x86

# Check _pure_is_corrupt for 2fdcc
from x86x64.translator._healing import HealingMixin
# can't instantiate easily - check hybrid heuristically

# Look at correlate: maybe ordered calls assign XcptFilter
# Check what x86 0x1a728 area is - earlier map had 1a728->31e65
print("\nmaps for chkstk region:")
for o in range(0x1a720, 0x1a7a0):
    if o in rmap:
        print(hex(o), "->", hex(rmap[o]))
