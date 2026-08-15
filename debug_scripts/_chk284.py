import pefile
pe = pefile.PE('build_univ284/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        trva = s.VirtualAddress
        with open('build_univ284/cmd_pure.exe', 'rb') as f:
            f.seek(s.PointerToRawData)
            d = f.read(s.SizeOfRawData)
        break

# Check crash site
print(f'At 0xABFD: {d[0xABFD-trva:0xABFD-trva+12].hex()}')
for off in range(0xABF8, 0xAC10):
    idx = off - trva
    if 0 <= idx < len(d):
        b = d[idx]
        c = chr(b) if 32 <= b < 127 else '.'
        print(f'0x{off:05X}: 0x{b:02X} {c}')

ok = 0; bad = 0
for i in range(len(d)-5):
    if d[i:i+3] == b'\x4c\x89\xec':
        if d[i+3:i+5] == b'\x41\x5d': ok += 1
        else: bad += 1; print(f'BAD at off 0x{i:X}: next={d[i+3:i+5].hex()}')
print(f'OK={ok} BAD={bad}')
