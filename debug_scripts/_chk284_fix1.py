import pefile
pe = pefile.PE('build_univ284/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        trva = s.VirtualAddress
        with open('build_univ284/cmd_pure.exe', 'rb') as f:
            f.seek(s.PointerToRawData)
            d = f.read(s.SizeOfRawData)
        break

# Check fixed site at 0x619D (RVA 0x719D)
off = 0x619D
print(f'Fixed site at 0x{off:X}:')
for o in range(off-4, off+20):
    idx = o - trva
    if 0 <= idx < len(d):
        b = d[idx]
        c = chr(b) if 32 <= b < 127 else '.'
        print(f'  0x{o:05X}: 0x{b:02X} {c}')
