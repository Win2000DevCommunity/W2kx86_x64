#!/usr/bin/env python3
import sys
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from x86_x64 import Win2000Translator, PE32Image, DynamicScanResult

src = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
pe = PE32Image(open(src, "rb").read())
tr = Win2000Translator(pe, win10_test_shim=True, source_path=src)
text_sec = next(s for s in pe.sections if s["name"].startswith(".text"))
text = pe.get_section_data(text_sec)
text_rva = text_sec["vaddr"]
func_rva = 0x1A035
func_bytes = tr._extract_function_bytes(func_rva, text, text_rva)
print(f"func_bytes len={len(func_bytes)} ends before 0x1A16A: {func_rva + len(func_bytes) <= 0x1A16A}")
out, rmap = tr._translate_function(func_rva, func_bytes, False, 0, section_rva=text_rva)
print(f"out len={len(out)}")
# find call to builder
for old_va, off in sorted(rmap.items()):
    rva = old_va - tr.old_base
    if 0x1A160 <= rva <= 0x1A180:
        print(f"  x86+0x{rva:X} -> out+0x{off:X}")
call_off = rmap.get(tr.old_base + 0x1A175)
if call_off:
    s = max(0, call_off - 64)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(bytes(out[s:call_off + 5]), s):
        print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")
print("r9d loads:", bytes(out).count(bytes.fromhex("448b4d40")))
