import pefile

pe = pefile.PE(r'C:/Users/win2000/Downloads/(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU/cmd.exe')

# Check what's at x86 0x31E00-0x31F00
target = 0x31E00
for s in pe.sections:
    va_start = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
    va_end = va_start + max(s.Misc_VirtualSize, s.SizeOfRawData)
    if va_start <= target < va_end:
        d = s.get_data()
        offset = target - va_start
        print(f'x86 0x{target:X} in section {s.Name.decode().strip()}')
        chunk = d[offset:offset + 0x100]
        # Hex dump
        for i in range(0, min(0x100, len(chunk)), 16):
            line = chunk[i:i+16]
            hexpart = ' '.join(f'{b:02x}' for b in line)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in line)
            addr = target + i
            print(f'  0x{addr:08X}: {hexpart:<48s} {ascii_part}')
        break

# Also check section headers
print("\nSections:")
for s in pe.sections:
    print(f'  {s.Name.decode():8s} VA=0x{s.VirtualAddress:08X} SizeRaw=0x{s.SizeOfRawData:X} VirtSize=0x{s.Misc_VirtualSize:X} Characteristics=0x{s.Characteristics:X}')
