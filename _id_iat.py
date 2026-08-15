# Identify IAT at x86 4ad011d4
import pefile
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
# find import by IAT rva
iat = 0x4ad011d4 - x86.OPTIONAL_HEADER.ImageBase
print('iat rva', hex(iat))
for e in x86.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        if imp.address and (imp.address - x86.OPTIONAL_HEADER.ImageBase) == iat:
            print(e.dll.decode(), imp.name)
# also 011dc
iat2 = 0x4ad011dc - x86.OPTIONAL_HEADER.ImageBase
for e in x86.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        if imp.address and (imp.address - x86.OPTIONAL_HEADER.ImageBase) == iat2:
            print('011dc', e.dll.decode(), imp.name)
