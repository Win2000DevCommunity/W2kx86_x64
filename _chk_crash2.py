import capstone, struct, pefile

pe = pefile.PE('build_out91/cmd_pure.exe')
text = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.text')
text_rva = text.VirtualAddress
data = text.get_data()

crash = 0x43DA5
off = crash - text_rva
raw = data[off:off+48]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
print(f'=== x64 disasm around 0x{crash:X} ===')
for insn in md.disasm(data[max(0,off-16):off+48], 0x80000000 + crash - 16):
    marker = '>>' if insn.address == 0x80000000 + crash else '  '
    print(f'  {marker} 0x{insn.address:X}: {insn.mnemonic:10s} {insn.op_str}')

print(f'\nRaw bytes at 0x{crash:X}:')
for i in range(0, len(raw), 16):
    chunk = raw[i:i+16]
    hex_str = ' '.join(f'{b:02X}' for b in chunk)
    print(f'  0x{crash+i:05X}: {hex_str}')

# Also check the caller
caller = 0x14AE1
off2 = caller - text_rva
raw2 = data[off2:off2+16]
print(f'\n=== Caller at 0x{caller:X} ===')
for insn in md.disasm(raw2, 0x80000000 + caller):
    print(f'  0x{insn.address:X}: {insn.mnemonic:10s} {insn.op_str}')
print('Raw:', ' '.join(f'{b:02X}' for b in raw2))
