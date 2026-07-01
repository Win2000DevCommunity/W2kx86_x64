"""Translate x86 cmd 0x6314 in isolation."""
import sys
sys.path.insert(0, ".")
from x86_x64 import PE32Image, DynamicScanResult, Win2000Translator

X86 = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
pe = PE32Image(open(X86, "rb").read())
tr = Win2000Translator(pe, dynamic_result=DynamicScanResult(), win10_test_shim=True, source_path=X86)

text_sec = next(s for s in pe.sections if s["name"].split("\0")[0] == ".text")
text_rva = text_sec["vaddr"]
text_data = pe.get_section_data(text_sec)

func_bytes = tr._extract_function_bytes(0x6314, text_data, text_rva)
print(f"extracted {len(func_bytes)} bytes from 0x6314")
out, chunk_map = tr._translate_function(
    0x6314, func_bytes, False, 0, chunk_base=0, section_rva=text_rva, global_rva_map={}, deferred_branches=[]
)
print(f"translated {len(out)} bytes")
print("entry off", chunk_map.get(tr.old_base + 0x6314))
print("first 64 bytes:", out[:64].hex())
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in md.disasm(out, 0x80000000):
    print(f"0x{ins.address-0x80000000:04X}: {ins.mnemonic} {ins.op_str}")
    if ins.address > 0x80000120:
        break
