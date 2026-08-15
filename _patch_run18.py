import struct, importlib
from pathlib import Path
from x86x64.pe.image32 import PE32Image
import x86x64.translator._misc as misc
importlib.reload(misc)

pe32 = PE32Image(Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
src_pe = bytearray(Path("build_univ18/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", src_pe, 0x3c)[0]
soh = struct.unpack_from("<H", src_pe, e+20)[0]; sec = e+24+soh
num = struct.unpack_from("<H", src_pe, e+6)[0]
TEXT_RVA=0x1000
for i in range(num):
    o=sec+i*40
    if src_pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", src_pe, o+8)
        text=bytearray(src_pe[rp:rp+rs]); text_rp=rp; break
rmap={}
for line in Path("build_univ18/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]= b - TEXT_RVA if b >= TEXT_RVA else b

class M(misc.MiscMixin):
    def __init__(self):
        self._cmd_no_hacks = True
        self.old_base = pe32.image_base
        self._fn_entry_rvas=set(); self._x86_cf=None
    def _resolve_call_target_off(self, out, target_rva, rva_map):
        return rva_map.get(target_rva)
    def _refine_shim_target_off(self, out, target_rva, tgt):
        return tgt

m=M()
td=pe32.get_section_data(pe32.section_for_rva(0x1000))
n=m._pure_patch_jcc_placeholders(text, rmap, td, TEXT_RVA)
print("patched", n, "left", text.count(b"\x0f\x00\x00\x00\x00\x00"))
src_pe[text_rp:text_rp+len(text)] = text
outp=Path("build_univ18/cmd_jccfix.exe")
outp.write_bytes(src_pe)
print("wrote", outp)
