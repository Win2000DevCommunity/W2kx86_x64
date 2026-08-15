import pefile

pe = pefile.PE('build_univ280/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        trva = s.VirtualAddress
        traw = s.PointerToRawData
        with open('build_univ280/cmd_pure.exe', 'rb') as f:
            for off in range(0xABE0, 0xAC10):
                fo = traw + (off - trva)
                f.seek(fo)
                b = f.read(1)[0]
                c = chr(b) if 32 <= b < 127 else '.'
                print(f'0x{off:04X}: 0x{b:02X} {c}')
        break
