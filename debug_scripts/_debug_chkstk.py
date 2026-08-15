"""Debug why _fix_chkstk_frame_alignment finds 0 fixes."""
import sys
sys.path.insert(0, '.')
from x86_x64 import Win2000Translator
import pefile

pe = pefile.PE('build_out120/cmd_pure.exe')
for s in pe.sections:
    if b'.text' in s.Name:
        data = bytearray(s.get_data())
        break

t = Win2000Translator.__new__(Win2000Translator)
t._chkstk_entry_cache = None
ck = t._pure_chkstk_entry_off(data)
print(f'_pure_chkstk_entry_off returned: 0x{ck:X}' if ck else 'None')

if ck is not None:
    count = 0
    for call_pos in range(len(data) - 5):
        if data[call_pos] != 0xE8:
            continue
        rel = int.from_bytes(data[call_pos+1:call_pos+5], 'little', signed=True)
        target = (call_pos + 5 + rel) & 0xFFFFFFFF
        if target != ck:
            continue
        count += 1
        
        # Check 7-byte REX.W form: 48 C7 C0 imm32
        is_rex = False
        if call_pos >= 7:
            w7 = data[call_pos-7:call_pos]
            if len(w7) >= 7 and w7[0] == 0x48 and w7[1] == 0xC7 and (w7[2] & 0xF8) == 0xC0:
                is_rex = True
        
        # Check 5-byte B8 form: B8 imm32
        is_b8 = False
        if call_pos >= 5:
            b = data[call_pos - 5]
            if 0xB8 <= b <= 0xBF and (b & 7) == 0:
                if call_pos < 6 or data[call_pos - 6] != 0x48:
                    is_b8 = True
        
        imm_off = call_pos - 4
        ov = int.from_bytes(data[imm_off:imm_off+4], 'little')
        tag = "REX" if is_rex else ("B8" if is_b8 else "???")
        prev = data[max(0, call_pos-12):call_pos].hex()
        print(f'  CALL 0x{call_pos:X}: {tag} 0x{ov:X} mod16={ov%16} prev={prev}')
    
    print(f'Total calls to _chkstk: {count}')
