"""Comprehensive post-build patcher for _chkstk alignment.

Fixes two issues:
1. The _chkstk epilogue has both old (mov rax,rsp; test; mov rsp,rcx) and 
   new (mov rax,[rsp+8]; and ecx,-16; mov esp,ecx; push rax; ret) code.
   The old code must be removed — it sets RSP before the new code runs,
   making the new code's RAX load read from the wrong stack location.
2. Frame sizes passed to _chkstk are not 16-byte aligned.
"""
import sys
import shutil

def patch_chkstk(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    
    # Find PE header and .text section
    pe_off = int.from_bytes(data[0x3C:0x40], 'little')
    num_sec = int.from_bytes(data[pe_off+6:pe_off+8], 'little')
    opt_hdr_size = int.from_bytes(data[pe_off+20:pe_off+22], 'little')
    sec_table = pe_off + 24 + opt_hdr_size
    
    text_raw_off = None
    text_raw_size = None
    for i in range(num_sec):
        off = sec_table + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode()
        if '.text' in name:
            text_raw_size = int.from_bytes(data[off+16:off+20], 'little')
            text_raw_off = int.from_bytes(data[off+20:off+24], 'little')
            break
    
    if text_raw_off is None:
        print("ERROR: .text section not found")
        return 0
    
    text_data = data[text_raw_off:text_raw_off + text_raw_size]
    
    # Find _chkstk entry
    sigs = [
        bytes.fromhex('3d0010000051488d4c2410'),
        bytes.fromhex('513d00100000488d4c2410'),
    ]
    ck_off = None
    for sig in sigs:
        ck_off = text_data.find(sig)
        if ck_off >= 0:
            break
    
    if ck_off is None:
        print("ERROR: _chkstk entry not found")
        return 0
    
    print(f"_chkstk entry at .text offset 0x{ck_off:X}")
    
    fixed = 0
    
    # --- Fix 1: Remove duplicate old epilogue code in _chkstk ---
    # The translator emits: 48 89 E0 85 01 48 89 CC (8 bytes of old code)
    # followed by: 48 8B 44 24 08 83 E1 F0 89 CC 50 C3 (11 bytes of new code)
    # The old code sets RSP before the new code loads RAX from [RSP+8],
    # corrupting the return address load. We need to NOP-out the old code.
    # Pattern to find: 48 89 E0 85 01 48 89 CC 48 8B 44 24 08 83 E1 F0 89 CC 50 C3
    hybrid = bytes.fromhex('4889e085014889cc488b44240883e1f089cc50c3')
    pos = text_data.find(hybrid)
    if pos >= 0:
        # NOP out the first 8 bytes (48 89 E0 85 01 48 89 CC) 
        # Replace with: 90 90 90 90 90 90 90 90 (8 NOPs)
        # This leaves the correct epilogue intact
        file_off = text_raw_off + pos
        print(f"  Fix _chkstk epilogue: NOP old code at file 0x{file_off:X}")
        for i in range(8):
            data[file_off + i] = 0x90
        fixed += 1
    
    # --- Fix 2: Align frame sizes passed to _chkstk ---
    for call_pos in range(len(text_data) - 5):
        if text_data[call_pos] != 0xE8:
            continue
        rel = int.from_bytes(text_data[call_pos+1:call_pos+5], 'little', signed=True)
        target = (call_pos + 5 + rel) & 0xFFFFFFFF
        if target != ck_off:
            continue
        
        # Scan backwards up to 64 bytes for mov rax/eax, imm32
        mov_imm_off = None
        for scan in range(call_pos - 7, max(0, call_pos - 64), -1):
            if scan + 7 <= call_pos:
                if (text_data[scan] == 0x48 and text_data[scan + 1] == 0xC7
                        and (text_data[scan + 2] & 0xF8) == 0xC0):
                    mov_imm_off = scan + 3
                    break
            if scan + 5 <= call_pos:
                b = text_data[scan]
                if (0xB8 <= b <= 0xBF and (b & 7) == 0
                        and (scan == 0 or text_data[scan - 1] != 0x48)):
                    mov_imm_off = scan + 1
                    break
        
        if mov_imm_off is None:
            continue
        
        old_val = int.from_bytes(text_data[mov_imm_off:mov_imm_off + 4], 'little')
        if old_val <= 0x28 or old_val >= 0x1000000:
            continue
        if old_val % 16 == 0:
            continue
        
        new_val = (old_val + 15) & ~15
        file_off = text_raw_off + mov_imm_off
        print(f"  Fix frame size: 0x{old_val:X} -> 0x{new_val:X} at file 0x{file_off:X}")
        data[file_off:file_off + 4] = new_val.to_bytes(4, 'little')
        fixed += 1
    
    if fixed > 0:
        backup = path + '.bak'
        shutil.copy(path, backup)
        with open(path, 'wb') as f:
            f.write(data)
        print(f"Applied {fixed} patches (backup at {backup})")
    else:
        print("No patches needed")
    
    return fixed

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'build_out123/cmd_pure.exe'
    patch_chkstk(path)
