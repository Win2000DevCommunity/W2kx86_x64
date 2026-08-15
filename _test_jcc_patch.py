import struct
from pathlib import Path
from x86x64.pe.image32 import PE32Image
from x86x64.translator._misc import MiscMixin
from x86x64.translator._env import HAS_CAPSTONE

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
pe = PE32Image(src)
data = Path("build_univ18/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", data, 0x3c)[0]
soh = struct.unpack_from("<H", data, e+20)[0]; sec = e+24+soh
num = struct.unpack_from("<H", data, e+6)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=bytearray(data[rp:rp+rs]); text_rva=va; break

rmap={}
for line in Path("build_univ18/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b

class M(MiscMixin):
    def __init__(self):
        self._cmd_no_hacks = True
        self.old_base = pe.image_base
    def _resolve_call_target_off(self, out, target_rva, rva_map):
        return rva_map.get(target_rva)
    def _refine_shim_target_off(self, out, target_rva, tgt):
        return tgt

m = M()
td = pe.get_section_data(pe.section_for_rva(0x1000))
print("HAS_CAPSTONE", HAS_CAPSTONE, "td", len(td), "text", len(text))
before = text.count(b"\x0f\x00\x00\x00\x00\x00")
print("before", before)
n = m._pure_patch_jcc_placeholders(text, rmap, td, 0x1000)
print("patched", n, "after", text.count(b"\x0f\x00\x00\x00\x00\x00"))
off=0x14d6c-0x1000
print("14d6c", text[off:off+6].hex())
print("b719 map", hex(rmap.get(0xb719,0)))
