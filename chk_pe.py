import pefile

pe = pefile.PE(r'C:/Users/win2000/Downloads/(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU/cmd.exe')
print(f'ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:X}')
print(f'Entry point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}')
print(f'SizeOfImage: 0x{pe.OPTIONAL_HEADER.SizeOfImage:X}')
print()

for i,s in enumerate(pe.sections):
    va_start = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
    va_end = va_start + max(s.Misc_VirtualSize, s.SizeOfRawData)
    print(f'  {s.Name.decode().strip():8s} VA=0x{s.VirtualAddress:X} SizeRaw=0x{s.SizeOfRawData:X} VirtSize=0x{s.Misc_VirtualSize:X}')
    print(f'           Range: 0x{va_start:X} - 0x{va_end:X}')

# Also check if 0x4AD22829 is in any section
target = 0x4AD22829
for i,s in enumerate(pe.sections):
    va_start = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
    va_end = va_start + max(s.Misc_VirtualSize, s.SizeOfRawData)
    if va_start <= target < va_end:
        print(f'\n  0x{target:X} is in section {s.Name.decode().strip()}')
        offset = target - va_start
        print(f'  Offset in section: 0x{offset:X}')
