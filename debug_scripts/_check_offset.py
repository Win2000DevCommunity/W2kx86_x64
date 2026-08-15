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
            # Output offset 0x29619 -> file offset
            file_off = text_raw + (0x29619 - text_rva)
            f.seek(file_off)
            data = f.read(4)
            print(f'Output offset 0x29619: bytes: {data.hex()}')
            # Also check 0x29621
            file_off2 = text_raw + (0x29621 - text_rva)
            f.seek(file_off2)
            data2 = f.read(4)
            print(f'Output offset 0x29621: bytes: {data2.hex()}')
            # Check 0x29617 (leave is C9)
            file_off3 = text_raw + (0x29617 - text_rva)
            f.seek(file_off3)
            data3 = f.read(6)
            print(f'Output offset 0x29617: bytes: {data3.hex()}')
        break
