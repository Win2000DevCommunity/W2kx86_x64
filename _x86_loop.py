import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

# Entry is at x86 RVA 0x1A610. main+0x4D535 maps roughly to
# 0x1A610 + (0x4D535 - 0x33FC4) = 0x33B81
# Let's disassemble the x86 around 0x33B00-0x33D00 to see the loop
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

start = 0x33B00 - 0x1000
end = 0x33D50 - 0x1000
print(f'x86 disasm around RVA 0x33B00-0x33D50:')
for ins in md.disasm(bytes(td[start:end]), pe.OPTIONAL_HEADER.ImageBase + tv + start):
    rva = ins.address - pe.OPTIONAL_HEADER.ImageBase
    if 0x33B00 <= rva <= 0x33D50:
        # Convert to approx x64 offset: x64 = rva - 0x1A610 + 0x33FC4
        x64_off = rva - 0x1A610 + 0x33FC4
        marker = ''
        if ins.mnemonic.startswith('call') or ins.mnemonic.startswith('j'):
            marker = '  <<<'
        print(f'  0x{rva:05X} -> main+0x{x64_off:X}: {ins.mnemonic} {ins.op_str}{marker}')
