import struct, importlib
from pathlib import Path
from x86x64.pe.image32 import PE32Image
import x86x64.translator._misc as misc
importlib.reload(misc)

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
        text=bytearray(data[rp:rp+rs]); break
rmap={}
for line in Path("build_univ18/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b

class M(misc.MiscMixin):
    def __init__(self):
        self._cmd_no_hacks = True
        self.old_base = pe.image_base
    def _resolve_call_target_off(self, out, target_rva, rva_map):
        return rva_map.get(target_rva)
    def _refine_shim_target_off(self, out, target_rva, tgt):
        return tgt

# wrap resolve to see
m=M()
td=pe.get_section_data(pe.section_for_rva(0x1000))
orig = m._pure_patch_jcc_placeholders

def wrapped(out, rva_map, text_data, text_rva):
    # Inline just the claim for 14d6c by running and checking
    n = orig(out, rva_map, text_data, text_rva)
    return n

n = wrapped(text, rmap, td, 0x1000)
print("n", n)
print("14d6c", text[0x14d6c-0x1000:0x14d6c-0x1000+6].hex())
print("14d76", text[0x14d76-0x1000:0x14d76-0x1000+6].hex())
# show first few patched sites
pat=b"\x0f"
# find 0f 8c that were previously 00
