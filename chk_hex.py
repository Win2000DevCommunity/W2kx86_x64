import pefile

pe = pefile.PE(r'C:/Users/win2000/Downloads/(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU/cmd.exe')

target = 0x4AD22829
for s in pe.sections:
    va_start = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
    va_end = va_start + max(s.Misc_VirtualSize, s.SizeOfRawData)
    if va_start <= target < va_end:
        d = s.get_data()
        offset = target - va_start
        print(f'Section: {s.Name.decode().strip()}')
        print(f'Section VA start: 0x{va_start:X}')
        print(f'Section VA size: 0x{max(s.Misc_VirtualSize, s.SizeOfRawData):X}')
        print(f'Data len: {len(d)}')
        print(f'Target offset: 0x{offset:X}')
        
        start = max(0, offset - 0x30)
        end = min(len(d), offset + 0x80)
        print(f'Chunk: 0x{start:X} - 0x{end:X}')
        chunk = d[start:end]
        # Print hex dump
        for i in range(0, len(chunk), 16):
            line = chunk[i:i+16]
            hexpart = ' '.join(f'{b:02x}' for b in line)
            addr = va_start + start + i
            print(f'  0x{addr:X}: {hexpart}')
        break
