import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = pefile.PE(r'C:/Users/win2000/Downloads/(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU/cmd.exe')
s = pe.sections[0]; d = s.get_data(); v = s.VirtualAddress
md = Cs(CS_ARCH_X86, CS_MODE_32)

# x86 source around 0x4AD22829 (which maps to x64 0x1303D)
start_rva = 0x22800
size = 0x200
chunk = d[start_rva - v:start_rva - v + size]
print(f'=== x86 around 0x4AD22800-0x4AD22A00 ===')
for i in md.disasm(chunk, 0x4AD00000 + start_rva):
    if 0x4AD22800 <= i.address <= 0x4AD22A00:
        marker = ' <---' if 0x4AD22829 <= i.address <= 0x4AD22850 else ''
        print(f'  0x{i.address:08X}: {i.mnemonic} {i.op_str}{marker}')
