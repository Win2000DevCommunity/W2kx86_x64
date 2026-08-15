import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from pathlib import Path
from x86x64.pe import PE32Image

src = PE32Image(Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
relocs = src.parse_relocations()
print("n relocs", len(relocs))
# find relocs near 0x1c6a8-0x1c6d0
for rva, rtype in relocs:
    if 0x1c690 <= rva <= 0x1c6e0:
        # read dword at rva
        sec = src.section_for_rva(rva)
        raw = src.get_section_data(sec)
        off = rva - sec["vaddr"]
        val = int.from_bytes(raw[off:off+4], "little")
        print("reloc rva=%#x type=%s val=%#x" % (rva, rtype, val))
