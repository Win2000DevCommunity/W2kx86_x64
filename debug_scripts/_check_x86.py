import pefile
import sys

inp = sys.argv[1]
pe = pefile.PE(inp)
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode()
    if name == '.text':
        text_rva = section.VirtualAddress
        text_raw = section.PointerToRawData
        print(f'.text RVA: 0x{text_rva:X}, Raw: 0x{text_raw:X}')
        with open(inp, 'rb') as f:
            # Check x86 bytes at 0x1513E and 0x15142
            for off_rva in [0x1513E, 0x15142, 0x1513A]:
                file_off = text_raw + (off_rva - text_rva)
                f.seek(file_off)
                data = f.read(16)
                print(f'x86 0x{off_rva:X}: {data.hex()}')
        break
