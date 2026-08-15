"""Check if x86 'pop esi' (0x5E) instructions are properly translated."""
import pefile

x86_pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
for s in x86_pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        x86_text_rva = s.VirtualAddress
        with open(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe', 'rb') as f:
            f.seek(s.PointerToRawData)
            x86_data = f.read(s.SizeOfRawData)
        break

# Read rva_map
rva_map = {}
with open('build_univ280/rva.txt') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) == 2:
            rva_map[int(parts[0], 16)] = int(parts[1], 16)

# Read x64 text
pe = pefile.PE('build_univ280/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        x64_text_rva = s.VirtualAddress
        with open('build_univ280/cmd_pure.exe', 'rb') as f:
            f.seek(s.PointerToRawData)
            x64_data = f.read(s.SizeOfRawData)
        break

# Find all 0x5E bytes (pop esi) in x86 text
# We need to disassemble to know if it's actually pop esi vs part of another instruction
# But for now, let's just check rva_map coverage

bad = 0
# Check every byte in x86 that is 0x5E (pop esi)
for i in range(len(x86_data) - 1):
    if x86_data[i] == 0x5E:
        rva = x86_text_rva + i
        # Check if it's a real pop esi (not part of another instruction)
        # Simple heuristic: check if previous byte is not a prefix or part of an instruction
        # For a more thorough check, we'd need to disassemble
        
        if rva in rva_map:
            x64_rva = rva_map[rva]
            x64_off = x64_rva - x64_text_rva
            if 0 <= x64_off < len(x64_data):
                x64_byte = x64_data[x64_off]
                if x64_byte != 0x5E:  # should be pop rsi
                    bad += 1
                    if bad <= 30:
                        # Show context
                        ctx_start = max(0, i - 4)
                        ctx_end = min(len(x86_data), i + 8)
                        ctx = x86_data[ctx_start:ctx_end]
                        print(f'BAD: x86 0x{rva:05X} ({ctx.hex()}) -> x64 RVA 0x{x64_rva:05X} byte=0x{x64_byte:02X}')
        else:
            bad += 1
            if bad <= 30:
                ctx_start = max(0, i - 4)
                ctx_end = min(len(x86_data), i + 8)
                ctx = x86_data[ctx_start:ctx_end]
                print(f'MISSING: x86 0x{rva:05X} ({ctx.hex()}) NOT IN rva_map')

print(f'\nTotal potentially bad/missing pop esi: {bad}')
