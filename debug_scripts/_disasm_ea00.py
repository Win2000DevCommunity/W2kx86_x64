import struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = pefile.PE('build_univ355/cmd_pure.exe')

for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Disassemble around main+0xEA00 (one of the _except_handler3 slot refs)
# File offset for main+0xEA00: RVA 0xEA00 -> file offset
target_rva = 0xEA00
for sec in pe.sections:
    if sec.VirtualAddress <= target_rva < sec.VirtualAddress + sec.Misc_VirtualSize:
        file_off = target_rva - sec.VirtualAddress + sec.PointerToRawData
        break

start = max(0, file_off - 60)
end = file_off + 60
print(f'x64 disasm around main+0x{target_rva:X}:')
for ins in md.disasm(bytes(td[start:end]), 0x80000000 + tv + start):
    off = ins.address - 0x80000000
    marker = ''
    if '0x800a4e' in ins.op_str:
        marker = '  <<< SHIM IAT REF'
    print(f'  main+0x{off:X}: {ins.mnemonic} {ins.op_str}{marker}')
