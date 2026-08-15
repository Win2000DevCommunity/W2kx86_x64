"""Debug: check _pure_mapped_entry_sane for 0x15142 at various x64 offsets."""
import sys
sys.path.insert(0, '.')
import pefile

pe = pefile.PE('build_univ275/cmd_pure.exe')
for s in pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        text_rva_64 = s.VirtualAddress
        text_raw_64 = s.PointerToRawData
        with open('build_univ275/cmd_pure.exe', 'rb') as f:
            f.seek(text_raw_64)
            x64_section_data = f.read(s.SizeOfRawData)
        break

x86_pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
for s in x86_pe.sections:
    if s.Name.rstrip(b'\x00').decode() == '.text':
        x86_text_rva = s.VirtualAddress
        x86_text_raw = s.PointerToRawData
        with open(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe', 'rb') as f:
            f.seek(x86_text_raw)
            x86_section_data = f.read(s.SizeOfRawData)
        break

from x86x64.translator._healing import HealingMixin

class Mock(HealingMixin):
    def __init__(self):
        self._cmd_no_hacks = True

t = Mock()

# output offset → index in x64_section_data: out_off - text_rva_64
# x86 rva → index in x86_section_data: rva - x86_text_rva
func_rva = 0x15142

# Display x86 bytes
x86_idx = func_rva - x86_text_rva
x86_head = x86_section_data[x86_idx:x86_idx+16]
print(f"x86 at 0x{func_rva:X}: {x86_head.hex()}")
print(f"x86[:2] == b'\\x8b\\xec'? {x86_head[:2] == b'\\x8b\\xec'}")
print(f"x86[:2] == b'\\x55\\x8b'? {x86_head[:2] == b'\\x55\\x8b'}")

for off in [0x29619, 0x29620, 0x29621, 0x2961D, 0x2961A, 0x2961B, 0x2961C]:
    idx = off - text_rva_64
    if 0 <= idx < len(x64_section_data) - 4:
        x64_head = x64_section_data[idx:idx+4]
        is_sane = t._pure_mapped_entry_sane(
            bytearray(x64_section_data), idx, func_rva, 
            x86_section_data, x86_text_rva)
        print(f"  out 0x{off:X} idx=0x{idx:X} ({x64_head.hex()}): sane={is_sane}")
