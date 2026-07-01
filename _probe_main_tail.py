"""Probe main_tail translation sizes."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from x86_x64 import Win2000Translator, PE32Image

src = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
pe = PE32Image(Path(src).read_bytes())
tr = Win2000Translator(pe, new_base=0x80000000, win10_test_shim=True)
sec = pe.section_for_rva(0xDBB0)
text_data = pe.get_section_data(sec)
hole_off = 0x3FDA0 - tr.text_rva
rva_map = {}

for x86_tail in range(0xDBB0, 0xDD00, 2):
    x86_end = 0xDE99
    t_off = x86_tail - sec['vaddr']
    e_off = x86_end - sec['vaddr']
    if t_off < 0 or e_off > len(text_data):
        continue
    blob = text_data[t_off:e_off]
    chunk_out, _ = tr._translate_function(
        x86_tail, blob, False, 0, chunk_base=hole_off,
        section_rva=tr.text_rva, global_rva_map=rva_map,
        deferred_branches=[])
    if chunk_out and len(chunk_out) <= 0x400:
        print(f"x86 0x{x86_tail:X} -> len 0x{len(chunk_out):X} head={chunk_out[:16].hex()}")
