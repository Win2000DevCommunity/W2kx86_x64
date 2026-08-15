import struct, sys
from pathlib import Path
sys.path.insert(0, ".")
from x86x64.pe import PE32Image
from x86x64.translator import Win2000Translator
from x86x64.pe.fixups import remap_section_rva

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
pe = PE32Image(src.read_bytes())
t = Win2000Translator(pe, pure=True, win10_test_shim=True)
t.new_base = 0x80000000
# load section map from univ96 pe roughly
newpe = Path("build_univ96/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", newpe, 0x3C)[0]
nsec = struct.unpack_from("<H", newpe, e+6)[0]
osz = struct.unpack_from("<H", newpe, e+20)[0]
soff = e+24+osz
# old sections
old_map = {}
for s in pe.sections:
    name = s["name"] if isinstance(s, dict) else s.Name
    # PE32Image API
print("sections attr", type(pe.sections), pe.sections[0] if pe.sections else None)
