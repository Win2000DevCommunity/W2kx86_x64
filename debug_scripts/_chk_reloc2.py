from pathlib import Path
from x86x64.pe import PE32Image
src = PE32Image(Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
print("dir_reloc", src.dir_reloc if hasattr(src,"dir_reloc") else None)
print([m for m in dir(src) if "reloc" in m.lower()])
rels = src.pe_relocs if hasattr(src, "pe_relocs") else None
print("pe_relocs", type(rels), len(rels) if rels is not None else None)
if rels:
    for item in list(rels)[:3]:
        print(" sample", item)
    hits = [x for x in rels if (x[0] if isinstance(x, tuple) else x) in range(0x1c690, 0x1c6e0) or (isinstance(x,tuple) and 0x1c690 <= x[0] <= 0x1c6e0)]
    print("hits", hits[:20], "n", len(hits))
