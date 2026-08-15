import pefile

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        text_rva = s.VirtualAddress
        with open(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe', 'rb') as f:
            f.seek(s.PointerToRawData)
            data = f.read(s.SizeOfRawData)
        break

# Show x86 around 0x655E and 0x6550
for base in [0x6550, 0x655E, 0x6560, 0x6540, 0x6562]:
    off = base - text_rva
    if 0 <= off < len(data) - 16:
        print(f'x86 0x{base:X}: {data[off:off+16].hex()}')
