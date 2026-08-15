import pefile

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        x86_text_rva = s.VirtualAddress
        with open(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe', 'rb') as f:
            f.seek(s.PointerToRawData)
            x86_data = f.read(s.SizeOfRawData)
        break

idx = 0x15142 - x86_text_rva
head = x86_data[idx:idx+16]
print(f"head = {head.hex()}")
print(f"head[:2] = {head[:2].hex()}")
expected = b'\x8b\xec'
print(f"expected = {expected.hex()}")
print(f"equal: {head[:2] == expected}")
print(f"type(head[:2]): {type(head[:2])}")
print(f"type(expected): {type(expected)}")
print(f"head[0]=0x{head[0]:02x}, head[1]=0x{head[1]:02x}")
print(f"expected[0]=0x{expected[0]:02x}, expected[1]=0x{expected[1]:02x}")
