import pefile
import struct

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

# Search for any reference to _except_handler3's IAT slot
# IAT VA for _except_handler3 = 0x4AD01260
iat_va = 0x4AD01260
iat_bytes = struct.pack('<I', iat_va)

print(f'Searching for references to _except_handler3 IAT VA 0x{iat_va:X}...')
count = 0
pos = 0
while True:
    idx = td.find(iat_bytes, pos)
    if idx < 0:
        break
    rva = tv + idx
    print(f'  Found at RVA 0x{rva:X}:')
    # Show context
    ctx = td[max(0,idx-10):idx+8]
    print(f'    Bytes: {ctx.hex()}')
    # Check what instruction this is
    print(f'    Byte at ref-6: {td[idx-6:idx].hex() if idx >= 6 else "N/A"}')
    count += 1
    pos = idx + 4
    if count >= 10:
        print(f'  ... (more)')
        break
print(f'Total references: {count}')

# Also search for the IAT RVA (0x1260, without image base)
iat_rva_bytes = struct.pack('<I', 0x1260)
print(f'\nSearching for IAT RVA 0x1260...')
count2 = 0
pos = 0
while True:
    idx = td.find(iat_rva_bytes, pos)
    if idx < 0:
        break
    rva = tv + idx
    print(f'  Found at RVA 0x{rva:X}: {td[idx-6:idx+6].hex() if idx>=6 else td[idx:idx+6].hex()}')
    count2 += 1
    pos = idx + 4
    if count2 >= 10:
        print(f'  ... (more)')
        break
print(f'Total references: {count2}')
