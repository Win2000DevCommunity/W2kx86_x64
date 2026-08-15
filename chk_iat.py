import pefile

pe = pefile.PE('build_out147/cmd_pure.exe')

# Find IAT entries
print("Import Directory:")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode()
    print(f"\n  DLL: {dll_name}")
    for imp in entry.imports:
        rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
        name = imp.name.decode()
        print(f"    0x{rva:08X} = {name}")

# Look up specific addresses
print("\n\nChecking specific IAT addresses:")
for target_rva in [0x78570, 0x79548]:
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
            if rva == target_rva:
                print(f"  0x{target_rva:X} = {entry.dll.decode()}!{imp.name.decode()}")
