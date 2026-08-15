import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

# x86 error check
pe = pefile.PE(r'C:/Users/win2000/Downloads/(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU/cmd.exe')
s = pe.sections[0]; d = s.get_data(); v = s.VirtualAddress
md = Cs(CS_ARCH_X86, CS_MODE_32)
chunk = d[0x14F07-v:0x14F25-v]
print('=== x86 error check at 0x14F07 ===')
for i in md.disasm(chunk, 0x4AD00000 + 0x14F07):
    print(f'  0x{i.address:08X}: {i.mnemonic} {i.op_str}')

print()

# x64 translation
pe2 = pefile.PE('build_out147/cmd_pure.exe')
text = pe2.sections[0]; d2 = text.get_data()
md2 = Cs(CS_ARCH_X86, CS_MODE_64)
chunk2 = d2[0x26A06 - 0x1000:0x26A30 - 0x1000]
print('=== x64 translation at 0x26A06 ===')
for i in md2.disasm(chunk2, 0x80026A06):
    print(f'  0x{i.address:X}: {i.mnemonic} {i.op_str}')
