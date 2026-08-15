import pefile
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
# dump IAT names around 11d0
for e in x86.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        if imp.address:
            rva = imp.address - x86.OPTIONAL_HEADER.ImageBase
            if 0x11c0 <= rva <= 0x1200:
                print(hex(rva), e.dll.decode(), imp.name)

# what is at 4ad011d4 in file - maybe delayed?
print('---')
# WaitForSingleObject import
for e in x86.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        if imp.name and b'Wait' in imp.name:
            print(hex(imp.address - x86.OPTIONAL_HEADER.ImageBase), e.dll.decode(), imp.name)
        if imp.name and b'longjmp' in imp.name:
            print('longjmp', hex(imp.address - x86.OPTIONAL_HEADER.ImageBase), e.dll.decode())
        if imp.name and b'setjmp' in imp.name:
            print('setjmp', hex(imp.address - x86.OPTIONAL_HEADER.ImageBase), e.dll.decode())
