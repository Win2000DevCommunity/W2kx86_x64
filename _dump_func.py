import pefile

pe = pefile.PE('build_univ280/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        trva = s.VirtualAddress
        traw = s.PointerToRawData
        with open('build_univ280/cmd_pure.exe', 'rb') as f:
            f.seek(traw)
            data = f.read(s.SizeOfRawData)
        break

# First copy at ~0x29620
print("=== First copy at 0x29620 ===")
for off in range(0x29620, 0x29660):
    idx = off - trva
    if 0 <= idx < len(data):
        b = data[idx]
        c = chr(b) if 32 <= b < 127 else '.'
        print(f'0x{off:05X}: 0x{b:02X} {c}')

# First copy epilogue at ~0xABD0
print("\n=== First copy epilogue at 0xABD0 ===")
for off in range(0xABD0, 0xAC10):
    idx = off - trva
    if 0 <= idx < len(data):
        b = data[idx]
        c = chr(b) if 32 <= b < 127 else '.'
        print(f'0x{off:05X}: 0x{b:02X} {c}')
