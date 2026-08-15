import pefile
pe = pefile.PE('build_univ283/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        trva = s.VirtualAddress
        traw = s.PointerToRawData
        with open('build_univ283/cmd_pure.exe', 'rb') as f:
            f.seek(traw)
            d = f.read(s.SizeOfRawData)
        break

# Check crash site
for off in range(0xABF8, 0xAC10):
    idx = off - trva
    if 0 <= idx < len(d):
        b = d[idx]
        c = chr(b) if 32 <= b < 127 else '.'
        print(f'0x{off:05X}: 0x{b:02X} {c}')

print(f'\nAt 0xABFD: {d[0xABFD-trva:0xABFD-trva+10].hex()}')
