"""Search for crash bytes in original x86 binary."""
import pefile

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
pattern = bytes([0xC4, 0x64, 0x24, 0x00, 0x00, 0xC3, 0x90, 0x90])

all_data = bytearray()
rva_base = {}
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode()
    data = s.get_data()
    rva_base[name] = (s.VirtualAddress, len(all_data))
    all_data.extend(data)

idx = all_data.find(pattern)
if idx >= 0:
    # Find which section
    for name, (rva, base) in sorted(rva_base.items(), key=lambda x: x[1][1], reverse=True):
        if idx >= base:
            file_rva = rva + (idx - base)
            print(f"Pattern found in section '{name}' at file-RVA 0x{file_rva:X} (file offset 0x{idx:X})")
            break
    # Show context
    ctx = all_data[max(0,idx-8):idx+24]
    for i in range(0, len(ctx), 8):
        chunk = ctx[i:i+8]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        print(f"  {hex_str}")
else:
    print("Pattern NOT found in original binary")

# Also search for just C4 64 24
short = bytes([0xC4, 0x64, 0x24])
idx2 = all_data.find(short)
if idx2 >= 0:
    print(f"\nShort pattern C4 64 24 found at file offset 0x{idx2:X}")
    ctx2 = all_data[max(0,idx2-4):idx2+16]
    hex_str = ' '.join(f'{b:02X}' for b in ctx2)
    print(f"  Context: {hex_str}")
