import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe2 = pefile.PE('build_out147/cmd_pure.exe')
text = pe2.sections[0]; d2 = text.get_data()
md2 = Cs(CS_ARCH_X86, CS_MODE_64)

# Disassemble around the exit ring at 0x13038
# x64 RVA 0x13038 = file offset 0x13038 - 0x1000 = 0x12038
start = 0x13000
size = 256
offset = start - 0x1000
chunk = d2[offset:offset + size]
print(f'=== x64 around 0x13000-0x13100 (exit ring area) ===')
for i in md2.disasm(chunk, 0x80000000 + start):
    print(f'  0x{i.address:X}: {i.mnemonic} {i.op_str}')
