import os, sys
os.environ["PURE"] = "1"
sys.path.insert(0, ".")
from pathlib import Path
from x86x64.pe import PE32Image
from x86x64.translator import Win2000Translator
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SRC = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
pe = PE32Image(SRC.read_bytes())
t = Win2000Translator(pe, win10_test_shim=True, source_path=str(SRC))
t._cmd_no_hacks = True
t.new_base = 0x80000000
t.text_rva = 0x1000
for s in pe.sections:
    name = s["name"].rstrip("\0").lower()
    if name == ".text": t._old_to_new_section[s["vaddr"]] = 0x1000
    elif name == ".data": t._old_to_new_section[s["vaddr"]] = 0x5c000
sec, text = pe.get_text_section()
md = Cs(CS_ARCH_X86, CS_MODE_64)
for rva, label in ((0x640e, "getenv"), (0x6581, "setenv")):
    code = t._extract_function_bytes(rva, text, sec.vaddr)
    out, _ = t._translate_function(rva, code, True, 2 if rva == 0x6581 else 1)
    homes = b"\x48\x89\x4c\x24\x08" in bytes(out)
    print(label, "shadow_homes", homes, "int3", out.count(0xCC))
