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

# Search for mov rsp, r13 (4C 89 EC) patterns
count_missing = 0
count_ok = 0
for i in range(len(data) - 5):
    if data[i:i+3] == b'\x4c\x89\xec':  # mov rsp, r13
        next_bytes = data[i+3:i+5]
        if next_bytes == b'\x41\x5d':  # pop r13 follows
            count_ok += 1
        else:
            count_missing += 1
            if count_missing <= 15:
                off = trva + i
                # Show surrounding bytes
                ctx_start = max(0, i - 4)
                ctx_end = min(len(data), i + 16)
                ctx = data[ctx_start:ctx_end]
                print(f'MISSING pop r13 at x64 off 0x{i:X} (RVA 0x{off:X}): next_2bytes={next_bytes.hex()} ctx={ctx.hex()}')

print(f'\nOK: {count_ok}, MISSING pop r13: {count_missing}')
