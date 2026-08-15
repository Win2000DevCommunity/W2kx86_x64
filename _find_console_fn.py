import pefile
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

# x86 IAT slots for SetFilePointer, GetConsoleOutputCP, GetCPInfo
iat_va = {
    'SetFilePointer': pe.OPTIONAL_HEADER.ImageBase + 0x119C,
    'GetConsoleOutputCP': pe.OPTIONAL_HEADER.ImageBase + 0x11A0,
    'GetCPInfo': pe.OPTIONAL_HEADER.ImageBase + 0x11A4,
}

# Find FF 15 calls to these slots
print('FF 15 calls to console CP functions:')
for name, va in iat_va.items():
    pattern = b'\xFF\x15' + struct.pack('<I', va)
    pos = 0
    hits = []
    while True:
        idx = td.find(pattern, pos)
        if idx < 0:
            break
        hits.append(tv + idx)
        pos = idx + 1
    print(f'  {name} (IAT 0x{va:X}): {len(hits)} calls at {[f"0x{h:X}" for h in hits[:6]]}')

# Now disassemble the x86 around the SetFilePointer/GetConsoleOutputCP calls
# Find the function that calls both SetFilePointer and GetConsoleOutputCP
sfp_va = iat_va['SetFilePointer']
gocp_va = iat_va['GetConsoleOutputCP']
sfp_pattern = b'\xFF\x15' + struct.pack('<I', sfp_va)

idx = td.find(sfp_pattern)
while idx >= 0:
    rva = tv + idx
    # Walk back to find the function start (previous ret or alignment)
    fn_start = idx
    for back in range(idx, max(0, idx - 0x400), -1):
        if td[back] in (0xC3, 0xC2):
            fn_start = back + 1
            break
    # Check if GetConsoleOutputCP is called within this function
    window = td[fn_start:idx + 0x200]
    if gocp_va is not None and struct.pack('<I', gocp_va) in window:
        print(f'\nFunction at x86 RVA 0x{tv+fn_start:X} calls SetFilePointer + GetConsoleOutputCP')
        print(f'  SetFilePointer call at 0x{rva:X}')
        # Disassemble the whole function
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        print(f'  Disassembly of x86 RVA 0x{tv+fn_start:X}:')
        count = 0
        for ins in md.disasm(bytes(td[fn_start:idx + 0x200]),
                             pe.OPTIONAL_HEADER.ImageBase + tv + fn_start):
            irva = ins.address - pe.OPTIONAL_HEADER.ImageBase
            if irva > rva + 0x120:
                break
            marker = ''
            if ins.mnemonic == 'call':
                marker = '  <<< CALL'
            print(f'    0x{irva:X}: {ins.mnemonic} {ins.op_str}{marker}')
            count += 1
            if count > 100:
                break
        break
    idx = td.find(sfp_pattern, idx + 1)
