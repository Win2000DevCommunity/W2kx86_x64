import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = pefile.PE(r'C:/Users/win2000/Downloads/(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU/cmd.exe')

# Find section for 0x4AD22829
target = 0x4AD22829
for s in pe.sections:
    va_start = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
    va_end = va_start + max(s.Misc_VirtualSize, s.SizeOfRawData)
    if va_start <= target < va_end:
        d = s.get_data()
        offset = target - va_start
        print(f'Target in section {s.Name.decode().strip()}, offset 0x{offset:X}')
        
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        chunk = d[offset - 0x30:offset + 0x80]
        for i in md.disasm(chunk, target - 0x30):
            marker = ' <---' if i.address == target else ''
            print(f'  0x{i.address:08X}: {i.mnemonic} {i.op_str}{marker}')
        break
