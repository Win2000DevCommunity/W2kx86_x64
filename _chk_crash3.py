"""Diagnose crash at main+0x9E67 - JE target landing in zero padding."""
import pefile, struct, capstone

pure_pe = pefile.PE('build_out92/cmd_pure.exe')
x86_pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

# Load rva_map
rmap = {}
with open('build_out92/rva.txt') as f:
    for line in f:
        p = line.split()
        if len(p) == 2:
            rmap[int(p[0], 16)] = int(p[1], 16)

crash_pure = 0x9E67
je_pure = 0x9C27
je_x86 = rmap.get(je_pure, 0)
crash_x86 = rmap.get(crash_pure, 0)

print(f"JE at pure 0x{je_pure:X} -> x86 0x{je_x86:X}")
print(f"Crash target pure 0x{crash_pure:X} -> x86 0x{crash_x86:X}")

# Disasm around crash in pure binary
text = next(s for s in pure_pe.sections if s.Name.rstrip(b'\x00') == b'.text')
text_rva = text.VirtualAddress
data = text.get_data()

md64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
print(f"\n=== Pure x64 around crash 0x{crash_pure:X} ===")
off = crash_pure - text_rva
for insn in md64.disasm(data[max(0,off-32):off+64], 0x80000000 + crash_pure - 32):
    marker = '>>' if insn.address == 0x80000000 + crash_pure else '  '
    addr = insn.address - 0x80000000
    x86 = rmap.get(addr)
    x86_str = f" (x86 0x{x86:X})" if x86 else ""
    print(f"  {marker} 0x{addr:05X}: {insn.mnemonic:10s} {insn.op_str}{x86_str}")

# Show raw bytes
raw = data[off:off+32]
print(f"\nRaw bytes at 0x{crash_pure:X}: {' '.join(f'{b:02X}' for b in raw)}")

# Check x86 original at crash_x86
print(f"\n=== x86 original at x86 0x{crash_x86:X} ===")
x86_text = next(s for s in x86_pe.sections if s.Name.rstrip(b'\x00') == b'.text')
x86_text_rva = x86_text.VirtualAddress
x86_data = x86_text.get_data()
x86_off = crash_x86 - x86_text_rva
if 0 <= x86_off < len(x86_data):
    md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for insn in md32.disasm(x86_data[max(0,x86_off-16):x86_off+32], 0x1000000 + crash_x86 - 16):
        marker = '>>' if insn.address == 0x1000000 + crash_x86 else '  '
        print(f"  {marker} 0x{crash_x86 - 16 + (insn.address - (0x1000000 + crash_x86 - 16)):05X}: {insn.mnemonic:10s} {insn.op_str}")
    raw_x86 = x86_data[max(0,x86_off-4):x86_off+20]
    print(f"Raw x86: {' '.join(f'{b:02X}' for b in raw_x86)}")
else:
    print(f"  x86 offset 0x{x86_off:X} out of range (section size=0x{len(x86_data):X})")
    # Check other sections
    for s in x86_pe.sections:
        if s.VirtualAddress <= crash_x86 < s.VirtualAddress + s.Misc_VirtualSize:
            name = s.Name.rstrip(b'\x00').decode()
            sec_data = s.get_data()
            sec_off = crash_x86 - s.VirtualAddress
            print(f"  Found in section '{name}' at offset 0x{sec_off:X}")
            if sec_off < len(sec_data):
                raw_sec = sec_data[sec_off:sec_off+20]
                print(f"  Raw: {' '.join(f'{b:02X}' for b in raw_sec)}")
            else:
                print(f"  Beyond raw data - BSS (zeros)")
            break

# Check rva_map entries near crash area
print(f"\n=== rva_map entries near 0x{crash_pure:X} ===")
nearby = [(p, x) for p, x in rmap.items() if abs(p - crash_pure) < 0x40]
nearby.sort()
for p, x in nearby:
    dist = p - crash_pure
    print(f"  pure 0x{p:05X} (dist={dist:+d}) -> x86 0x{x:05X}")

# Check JE source x86 section and disasm
print(f"\n=== x86 original at JE source 0x{je_x86:X} ===")
for s in x86_pe.sections:
    if s.VirtualAddress <= je_x86 < s.VirtualAddress + s.Misc_VirtualSize:
        name = s.Name.rstrip(b'\x00').decode()
        sec_off = je_x86 - s.VirtualAddress
        sec_data = s.get_data()
        print(f"  Section '{name}' offset 0x{sec_off:X} (raw_size=0x{len(sec_data):X})")
        if sec_off < len(sec_data):
            md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            for insn in md32.disasm(sec_data[max(0,sec_off-16):sec_off+32], 0x1000000 + je_x86 - 16):
                marker = '>>' if insn.address == 0x1000000 + je_x86 else '  '
                print(f"  {marker} 0x{insn.address - 0x1000000:05X}: {insn.mnemonic:10s} {insn.op_str}")
        else:
            print(f"  Beyond raw data - BSS (all zeros at runtime)")
        break
else:
    print(f"  x86 0x{je_x86:X} not in any section!")

# Also check the intended JE target: what x86 RVA should the JE go to?
# The JE at pure 0x9C27 should correspond to a conditional branch in x86
# Let's look at what x86 code maps to the pure code around the JE
print(f"\n=== Pure code around JE at 0x{je_pure:X} ===")
off_je = je_pure - text_rva
md64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for insn in md64.disasm(data[max(0,off_je-32):off_je+32], 0x80000000 + je_pure - 32):
    addr = insn.address - 0x80000000
    x86_m = rmap.get(addr)
    marker = '>>' if addr == je_pure else '  '
    x86_s = f"(x86 0x{x86_m:X})" if x86_m else ""
    print(f"  {marker} 0x{addr:05X}: {insn.mnemonic:10s} {insn.op_str} {x86_s}")
