import pefile
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# Disassemble x86 around 0xC500-0xC850 (GetConsoleOutputCP + GetCPInfo region)
start = 0xC500 - 0x1000
end = 0xC850 - 0x1000
print(f'x86 disasm 0xC500-0xC850:')
for ins in md.disasm(bytes(td[start:end]), pe.OPTIONAL_HEADER.ImageBase + tv + start):
    rva = ins.address - pe.OPTIONAL_HEADER.ImageBase
    marker = ' <<<' if ins.mnemonic in ('call', 'ret') or ins.mnemonic.startswith('j') else ''
    print(f'  0x{rva:X}: {ins.mnemonic} {ins.op_str}{marker}')
