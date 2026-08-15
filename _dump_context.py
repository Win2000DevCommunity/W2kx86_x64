import pefile
import sys

pe = pefile.PE(sys.argv[1])
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode()
    if name == '.text':
        text_rva = section.VirtualAddress
        text_raw = section.PointerToRawData
        print(f'.text RVA: 0x{text_rva:X}, Raw: 0x{text_raw:X}')
        with open(sys.argv[1], 'rb') as f:
            for off in range(0x29610, 0x29630):
                file_off = text_raw + (off - text_rva)
                f.seek(file_off)
                b = f.read(1)[0]
                print(f'  0x{off:X}: 0x{b:02X} ({chr(b) if 32 <= b < 127 else "."})')
        break
