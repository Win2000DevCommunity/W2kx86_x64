#!/usr/bin/env python3
"""Translate the cmd function containing 0x1A16A and dump call setup."""
import struct
import sys
sys.path.insert(0, ".")
from x86_x64 import Win2000Translator, PE32Image

src = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
data = open(src, "rb").read()
pe = PE32Image(data)
tr = Win2000Translator(
    pe, old_base=0x4AD00000, win10_test_shim=True,
    source_path=src, ntdll_path=r"C:\Windows\System32\ntdll.dll")
# function containing builder caller — scan for push ff7520 before call to 0x1A217
text = pe.section_data(".text")
text_rva = pe.section_rva(".text")
md = tr.md
insns = list(md.disasm(text, 0x4AD00000 + text_rva))
for i, ins in enumerate(insns):
    if ins.address - 0x4AD00000 == 0x1A16A:
        # walk back to push ebp prologue
        start = i
        while start > 0 and insns[start].mnemonic != "push":
            start -= 1
        while start > 0 and not (insns[start].mnemonic == "push"
                                 and insns[start].operands
                                 and insns[start].operands[0].type == 1
                                 and insns[start].operands[0].reg == 5):
            start -= 1
        func_rva = insns[start].address - 0x4AD00000
        end = i + 20
        func_bytes = text[func_rva - text_rva:end - text_rva + text_rva - func_rva]
        func_bytes = text[func_rva - text_rva:func_rva - text_rva + (insns[end].address - insns[start].address)]
        break
else:
    raise SystemExit("not found")

func_rva = 0x19E00  # approximate — use known outer parse fn
for fr in range(0x19000, 0x1B000, 0x10):
    chunk = text[fr - text_rva:fr - text_rva + 0x400]
    out, rmap = tr._translate_function(fr, chunk, False, 0, section_rva=text_rva)
    if any(old - 0x4AD00000 == 0x1A175 for old in rmap):
        print(f"func rva=0x{fr:X} out_len={len(out)}")
        # show mapping around call
        for old in sorted(rmap):
            o = old - 0x4AD00000
            if 0x1A160 <= o <= 0x1A180:
                print(f"  x86+0x{o:X} -> out+0x{rmap[old]:X}")
        # disasm output around mapped call
        call_off = rmap.get(0x4AD00000 + 0x1A175)
        if call_off:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            md64 = Cs(CS_ARCH_X86, CS_MODE_64)
            s = max(0, call_off - 48)
            for ins in md64.disasm(bytes(out[s:call_off + 8]), s):
                print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")
        break
