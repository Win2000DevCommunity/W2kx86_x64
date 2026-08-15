import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = pefile.PE(r'C:/Users/win2000/Downloads/(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU/cmd.exe')
for i,s in enumerate(pe.sections):
    print(f'  Section {i}: {s.Name.decode().strip()} VA=0x{s.VirtualAddress:X} Size=0x{s.SizeOfRawData:X}')

s = pe.sections[0]; v = s.VirtualAddress
print(f'\nText section: VA=0x{v:X}, Size=0x{s.SizeOfRawData:X}')
print(f'Data len={len(s.get_data())}')

target_rva = 0x22829
offset_in_data = target_rva - v
print(f'Target RVA 0x{target_rva:X} -> offset 0x{offset_in_data:X} in section data')
d = s.get_data()
if offset_in_data >= 0 and offset_in_data < len(d):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    chunk = d[offset_in_data-0x20:offset_in_data+0x80]
    print(f'\n=== x86 around 0x4AD22829 ===')
    for i in md.disasm(chunk, 0x4AD00000 + target_rva - 0x20):
        marker = ' <---' if i.address >= 0x4AD22829 else ''
        print(f'  0x{i.address:08X}: {i.mnemonic} {i.op_str}{marker}')
