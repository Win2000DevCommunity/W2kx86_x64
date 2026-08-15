#!/usr/bin/env python3
import pefile
import sys

pe = pefile.PE(sys.argv[1])
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode('utf-8', 'ignore')
    if 'w2kshim' in dll.lower():
        for imp in entry.imports:
            name = imp.name.decode() if imp.name else 'ordinal_only'
            print(f"  hint={imp.hint:04X} ord={imp.ordinal} name={name}")
