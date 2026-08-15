import pefile

pe = pefile.PE('build_univ281/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        trva = s.VirtualAddress
        traw = s.PointerToRawData
        with open('build_univ281/cmd_pure.exe', 'rb') as f:
            f.seek(traw)
            data = f.read(s.SizeOfRawData)
        break

# Check bytes at 0xABF8-0xAC0A (crash site area) for build 281
for off in range(0xABF8, 0xAC10):
    idx = off - trva
    if 0 <= idx < len(data):
        b = data[idx]
        c = chr(b) if 32 <= b < 127 else '.'
        print(f'0x{off:05X}: 0x{b:02X} {c}')

# Also check mov rsp,r13 count
count_ok = 0
count_bad = 0
for i in range(len(data) - 5):
    if data[i:i+3] == b'\x4c\x89\xec':
        if data[i+3:i+5] == b'\x41\x5d':
            count_ok += 1
        else:
            count_bad += 1
            if count_bad <= 5:
                print(f'BAD mov rsp,r13 at off 0x{i:X}: next={data[i+3:i+5].hex()}')
print(f'OK: {count_ok}, BAD: {count_bad}')
