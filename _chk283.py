import pefile
pe = pefile.PE('build_univ283/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        with open('build_univ283/cmd_pure.exe', 'rb') as f:
            f.seek(s.PointerToRawData)
            d = f.read(s.SizeOfRawData)
        break
ok = 0; bad = 0
for i in range(len(d)-5):
    if d[i:i+3] == b'\x4c\x89\xec':
        if d[i+3:i+5] == b'\x41\x5d': ok += 1
        else:
            bad += 1
            if bad <= 5:
                print(f'BAD at off 0x{i:X}: next={d[i+3:i+5].hex()}')
print(f'OK={ok} BAD={bad}')
