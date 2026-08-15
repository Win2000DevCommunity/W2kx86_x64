import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = pefile.PE('build_out147/cmd_pure.exe')
d = pe.sections[0].get_data()
md = Cs(CS_ARCH_X86, CS_MODE_64)

# Function at 0x187EE
start = 0x187E0
size = 0x80
chunk = d[start - 0x1000 : start - 0x1000 + size]
print(f'=== x64 function at 0x187E0 ===')
for i in md.disasm(chunk, 0x80000000 + start):
    marker = ' <--- CALL TARGET' if i.address == 0x800187EE else ''
    print(f'  0x{i.address:X}: {i.mnemonic} {i.op_str}{marker}')
    if i.mnemonic == 'ret' or i.mnemonic == 'jmp':
        if i.address > 0x80018810:
            break
