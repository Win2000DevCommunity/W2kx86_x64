import pefile

pe = pefile.PE(r'C:/Users/win2000/Downloads/(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU/cmd.exe')

# Direct hex dump at offset 0x7E00 in .rsrc section
rsrc = pe.sections[2]
d = rsrc.get_data()
print(f'.rsrc section: VA=0x{rsrc.VirtualAddress:X}, raw_size=0x{rsrc.SizeOfRawData:X}, data_len={len(d)}')

# Target x86 RVA = 0x31E00, offset in section = 0x31E00 - 0x2A000 = 0x7E00
target_rva = 0x31E00
offset = target_rva - rsrc.VirtualAddress  # 0x31E00 - 0x2A000 = 0x7E00
print(f'RVA 0x{target_rva:X} -> section offset 0x{offset:X}')

if offset >= 0 and offset < len(d):
    chunk = d[offset:offset + 0x60]
    for i in range(0, len(chunk), 16):
        line = chunk[i:i+16]
        hexpart = ' '.join(f'{b:02x}' for b in line)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in line)
        addr = 0x4AD00000 + target_rva + i
        print(f'  0x{addr:08X}: {hexpart:<48s} {ascii_part}')
else:
    print(f'OFFSET {offset} OUT OF RANGE (data len {len(d)})')
