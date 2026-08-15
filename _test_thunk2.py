import sys
sys.path.insert(0, '.')

from x86x64.translator import Win2000Translator
from x86x64.pe.image32 import PE32Image

data = open(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe', 'rb').read()
pe = PE32Image(data)

t = Win2000Translator(pe, win10_test_shim=True, verbose=False)

# Set cmd_no_hacks like the pure build does
t._cmd_no_hacks = True

# Plan IAT map
est = t._estimate_idata_rva()
t._plan_iat_map_early(est)
print(f'est_idata = 0x{est:X}')
print(f'map[0x1260] = 0x{t._iat_rva_map.get(0x1260, 0):X}')
print(f'map[0x1264] = 0x{t._iat_rva_map.get(0x1264, 0):X}')

# Check _resolve_iat_slot_va for both slots
print(f'slot va for 0x4AD01260 = 0x{t._resolve_iat_slot_va(0x4AD01260):X}')
print(f'slot va for 0x4AD01264 = 0x{t._resolve_iat_slot_va(0x4AD01264):X}')

# Now check function discovery: is 0x1A766 a function entry?
print(f'\n_fn_entry_rvas has 0x1A760: {0x1A760 in getattr(t, "_fn_entry_rvas", set())}')
print(f'_fn_entry_rvas has 0x1A766: {0x1A766 in getattr(t, "_fn_entry_rvas", set())}')

# Check how the x86 CF analysis sees these
x86_cf = getattr(t, '_x86_cf', None)
print(f'_x86_cf = {x86_cf}')

# Simulate the call emission path: what does the translator do for
# `call 0x4AD1A766`?
target_rva = 0x1A766
iat_slot = t._ff25_iat_slot_at_rva(target_rva)
print(f'\n_ff25_iat_slot_at_rva(0x1A766) = {hex(iat_slot) if iat_slot else None}')

# Now check what _resolve_call_target_off does for target 0x1A766 (the thunk)
# Create a dummy output buffer with the translated thunk code
out = bytearray()
# Simulate: what would the thunk translate to?
# Emit the IAT jmp for both thunks
from x86x64.translator._encoding import EncodingMixin
slot_va_260 = t._resolve_iat_slot_va(0x4AD01260)
slot_va_264 = t._resolve_iat_slot_va(0x4AD01264)
print(f'If both thunks translated: jmp through 0x{slot_va_260:X} and 0x{slot_va_264:X}')
