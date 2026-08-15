import os, sys, struct
os.environ["PURE"]="1"
sys.path.insert(0,".")
from pathlib import Path
from x86x64.pe import PE32Image

SRC = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
pe = PE32Image(SRC.read_bytes())
# measure zero run at 0x4ad22b00
rva = 0x4ad22b00 - pe.image_base
sec = pe.section_for_rva(rva)
raw = pe.get_section_data(sec)
off = rva - sec["vaddr"]
i = off
while i < len(raw) and raw[i] == 0:
    i += 1
print("zero run", hex(i-off), "chars", (i-off)//2)
