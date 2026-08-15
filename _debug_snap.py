import pefile, struct, sys
sys.path.insert(0, '.')
import x86_x64

pe = pefile.PE('build_out161/cmd_pure.exe')
text = next(s for s in pe.sections if b'.text' in s.Name)
blob = bytearray(text.get_data())

x86_pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
x86_text = next(s for s in x86_pe.sections if b'.text' in s.Name)
x86_data = x86_text.get_data()
x86_rva = x86_text.VirtualAddress

rva_map = {}
with open('build_out161/rva.txt', 'r', encoding='utf-8') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) == 2:
            rva_map[int(parts[0], 16)] = int(parts[1], 16)

# Manual debug: check the call at 0x13BD6
cp = 0x13BD6 - text.VirtualAddress  # blob offset of call
call_bytes = blob[cp:cp+5]
rel = struct.unpack_from('<i', call_bytes, 1)[0]
tgt_blob = cp + 5 + rel
print(f'Call at blob 0x{cp:X}: rel={rel}, tgt_blob=0x{tgt_blob:X}')

# Check prologue at tgt_blob
AW = b'\x41\x55\x49\x89\xe5\x48\x83\xec\x20\x48\x83\xe4\xf0'
prologue_start = tgt_blob
print(f'Prologue at 0x{prologue_start:X}: match={blob[prologue_start:prologue_start+13] == AW}')
print(f'Self-ref: {prologue_start <= tgt_blob < cp}')

# Reverse lookup for x86 source - UNLIMITED scan
rev = {x64: x86 for x86, x64 in rva_map.items() if 0 <= x64 < len(blob)}
found = None
for step in range(1, cp + 1):
    candidate = cp - step
    if candidate < 0:
        break
    x86_r = rev.get(candidate)
    if x86_r is not None:
        found = (candidate, x86_r)
        break
print(f'Reverse lookup: step={step}, found={found}')

if found:
    x64_off, x86_src = found
    print(f'x86 source: 0x{x86_src:05X}')
    x86_off = x86_src - x86_rva
    hx = x86_data[x86_off:x86_off+8].hex() if 0 <= x86_off < len(x86_data)-8 else 'OOB'
    print(f'x86 bytes at 0x{x86_off:X}: {hx}')
    # The call is at x86_src + 2 (after push 8)
    if 0 <= x86_off + 2 < len(x86_data) - 5 and x86_data[x86_off + 2] == 0xE8:
        x86_rel = struct.unpack_from('<i', x86_data, x86_off + 3)[0]
        x86_tgt = (x86_src + 2 + 5 + x86_rel) & 0xFFFFFFFF
        new_tgt = rva_map.get(x86_tgt)
        print(f'x86 call target: 0x{x86_tgt:05X}, x64 new_tgt: 0x{new_tgt:X}' if new_tgt else f'x86 call target: 0x{x86_tgt:05X}, NO RVA')
        if new_tgt:
            print(f'Current tgt=0x{tgt_blob:X} -> new_tgt=0x{new_tgt:X} (diff={new_tgt - tgt_blob})')
    else:
        print(f'No E8 at offset +2')
