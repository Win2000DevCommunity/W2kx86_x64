#!/usr/bin/env python3
import sys
sys.path.insert(0, ".")
from x86_x64 import PE32Image, discover_function_rvas, DynamicScanResult

src = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
pe = PE32Image(open(src, "rb").read())
text = pe.get_section_data(".text")
trva = pe.get_section_rva(".text")
funcs = discover_function_rvas(pe, text, trva, DynamicScanResult())
for fr in funcs:
    if fr <= 0x1A175 < fr + 0x2000:
        inside = "inside" if fr <= 0x1A16A else "OUTSIDE"
        print(f"func va=0x{fr:X} contains call 0x1A175, push 0x1A16A {inside}")
