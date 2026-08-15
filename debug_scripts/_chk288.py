import pefile
pe = pefile.PE('build_univ288/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        trva = s.VirtualAddress
        with open('build_univ288/cmd_pure.exe', 'rb') as f:
            f.seek(s.PointerToRawData)
            d = f.read(s.SizeOfRawData)
        break

# Show bytes from 0xABF0 to 0xAC20
for off in range(0xABF0, 0xAC20):
    idx = off - trva
    if 0 <= idx < len(d):
        b = d[idx]
        c = chr(b) if 32 <= b < 127 else '.'
        print(f'0x{off:05X}: 0x{b:02X} {c}')
