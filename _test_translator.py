import sys
sys.path.insert(0, '.')

from x86x64.translator import Win2000Translator
from x86x64.pe.image32 import PE32Image

data = open(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe', 'rb').read()
pe = PE32Image(data)

# Check translator init signature
import inspect
sig = inspect.signature(Win2000Translator.__init__)
print(f'Win2000Translator.__init__ params: {sig}')

# Create with minimal args
t = Win2000Translator(pe, win10_test_shim=True)

# Test the thunk resolution
print(f'\nold_base=0x{t.old_base:X}')
print(f'image_size=0x{t.pe.image_size:X}')

slot_260 = t._ff25_iat_slot_at_rva(0x1A760)
slot_264 = t._ff25_iat_slot_at_rva(0x1A766)
print(f'_ff25_iat_slot_at_rva(0x1A760) = {hex(slot_260) if slot_260 else None}')
print(f'_ff25_iat_slot_at_rva(0x1A766) = {hex(slot_264) if slot_264 else None}')

# Test _imm_to_old_rva
print(f'_imm_to_old_rva(0x4AD01260) = {hex(t._imm_to_old_rva(0x4AD01260))}')
print(f'_imm_to_old_rva(0x4AD01264) = {hex(t._imm_to_old_rva(0x4AD01264))}')

# Plan the IAT map early and check values
t._plan_iat_map_early(0x10000)
print(f'\n_iat_rva_map[0x1260] = 0x{t._iat_rva_map.get(0x1260, 0):X}')
print(f'_iat_rva_map[0x1264] = 0x{t._iat_rva_map.get(0x1264, 0):X}')
print(f'_iat_rva_map[0x1284] = 0x{t._iat_rva_map.get(0x1284, 0):X}')
print(f'_iat_rva_map[0x1260] = 0x{t._iat_rva_map.get(0x1260, 0):X}')
print(f'_iat_rva_map[0x1264] = 0x{t._iat_rva_map.get(0x1264, 0):X}')

# Test _resolve_iat_slot_va
slot_va_260 = t._resolve_iat_slot_va(0x4AD01260)
slot_va_264 = t._resolve_iat_slot_va(0x4AD01264)
print(f'\n_resolve_iat_slot_va(0x4AD01260) = {hex(slot_va_260)}')
print(f'_resolve_iat_slot_va(0x4AD01264) = {hex(slot_va_264)}')
print(f'Expected slot 10 (except_handler3) = 0x{t.new_base + t._iat_rva_map[0x1260]:X}')
print(f'Expected slot 11 (setjmp3)        = 0x{t.new_base + t._iat_rva_map[0x1264]:X}')
