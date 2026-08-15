import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = pefile.PE(r'C:/Users/win2000/Downloads/(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU/cmd.exe')
s = pe.sections[0]; d = s.get_data(); v = s.VirtualAddress

# x86 function at 0xDB12
target = 0xDB00
offset = target - v
md = Cs(CS_ARCH_X86, CS_MODE_32)
chunk = d[offset:offset + 0x100]
print(f'=== x86 function around 0x4AD0DB12 ===')
for i in md.disasm(chunk, 0x4AD00000 + target):
    marker = ' <---' if i.address == 0x4AD0DB12 else ''
    print(f'  0x{i.address:08X}: {i.mnemonic} {i.op_str}{marker}')
    if i.mnemonic == 'ret' and i.address > 0x4AD0DB20:
        break
