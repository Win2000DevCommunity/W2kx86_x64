import pefile
import struct

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

# Find FF 25 thunks in the IAT area (0x10BC-0x12E0)
print('FF 25 (jmp [iat]) thunks near shim IAT slots:')
i = 0
c = 0
while i < len(td) - 6:
    if td[i:i+2] == b'\xff\x25':
        sl = struct.unpack_from('<I', td, i + 2)[0]
        sr = sl - pe.OPTIONAL_HEADER.ImageBase
        if 0x1060 <= sr <= 0x1300:
            print(f'  RVA 0x{tv+i:X}: FF 25 -> IAT RVA 0x{sr:X}')
            c += 1
        i += 6
    else:
        i += 1
print(f'Total: {c}')

# Also check what's at RVA ~0x1260 in the original x86
print(f'\nBytes at RVA 0x1260: {td[0x1260-0x1000:0x1260-0x1000+20].hex()}')
print(f'Bytes at RVA 0x11E4: {td[0x11E4-0x1000:0x11E4-0x1000+20].hex()}')
print(f'Bytes at RVA 0x11EC: {td[0x11EC-0x1000:0x11EC-0x1000+20].hex()}')

# Now check what function has its IAT thunk at each RVA
# The IAT thunks are usually at the beginning of the .text section
# or interspersed with code.

# Let's check the FF 25 at the crash site RVA
# We need to find the x86 RVA that maps to main+0x4D114
# But since we don't have rva_map, let's search for FF 15 calls near the 
# _except_handler3 IAT area
print('\nFF 15 (call [iat]) calls to shim IAT slots:')
for func_name in ['longjmp', 'towupper', '_get_osfhandle', 'towlower', 
                   '_except_handler3', '_setjmp3', '_seh_longjmp_unwind']:
    # Find the IAT RVA for this function
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name and imp.name.decode() == func_name:
                iat_rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                # Search for FF 15 calls to this IAT
                pattern = b'\xFF\x15' + struct.pack('<I', imp.address)
                count = td.count(pattern)
                if count > 0:
                    print(f'  {func_name} (IAT 0x{iat_rva:X}): {count} FF 15 calls')
                break
