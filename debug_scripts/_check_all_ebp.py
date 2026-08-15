import pefile
import sys

# Read x86 text
x86_pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
for s in x86_pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        x86_text_rva = s.VirtualAddress
        with open(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe', 'rb') as f:
            f.seek(s.PointerToRawData)
            x86_data = f.read(s.SizeOfRawData)
        break

# Read x64 text
pe = pefile.PE('build_univ280/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        x64_text_rva = s.VirtualAddress
        with open('build_univ280/cmd_pure.exe', 'rb') as f:
            f.seek(s.PointerToRawData)
            x64_data = f.read(s.SizeOfRawData)
        break

# Check rva_map for entries where x86 is mov ebp,esp but x64 is not mov rbp,rsp
bad = 0
with open('build_univ280/rva.txt') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        x86_rva = int(parts[0], 16)
        x64_rva = int(parts[1], 16)
        # Check if x86 at this RVA is mov ebp,esp (8B EC)
        x86_off = x86_rva - x86_text_rva
        if 0 <= x86_off < len(x86_data) - 1:
            if x86_data[x86_off:x86_off+2] == b'\x8b\xec':
                # Check if x64 at mapped offset is mov rbp,rsp (48 89 E5)
                x64_off = x64_rva - x64_text_rva
                if 0 <= x64_off < len(x64_data) - 2:
                    if x64_data[x64_off:x64_off+3] != b'\x48\x89\xe5':
                        bad += 1
                        if bad <= 20:
                            print(f'BAD: x86 0x{x86_rva:X} -> x64 RVA 0x{x64_rva:X} '
                                  f'(offset 0x{x64_off:X}, bytes={x64_data[x64_off:x64_off+3].hex()})')
print(f'Total bad mov-ebp entries: {bad}')
