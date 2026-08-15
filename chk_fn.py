import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = pefile.PE(r'C:/Users/win2000/Downloads/(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU/cmd.exe')

# Function at 0x4AD31E24 (which maps to x64 0x187E0 area)
target = 0x4AD31E24
# Find section
for s in pe.sections:
    va_start = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
    va_end = va_start + max(s.Misc_VirtualSize, s.SizeOfRawData)
    if va_start <= target < va_end:
        d = s.get_data()
        offset = target - va_start
        print(f'x86 function at 0x{target:X} in {s.Name.decode().strip()}')
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        chunk = d[offset:offset + 0x100]
        for i in md.disasm(chunk, target):
            marker = ' <--- ENTRY' if i.address == 0x4AD31E41 else ''
            print(f'  0x{i.address:08X}: {i.mnemonic} {i.op_str}{marker}')
            if i.mnemonic == 'ret' and i.address > target + 10:
                break
        break
