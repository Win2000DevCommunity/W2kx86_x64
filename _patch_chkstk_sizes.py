"""Standalone post-build patcher: round _chkstk frame sizes to 16-byte multiples.

Run after every build: python _patch_chkstk_sizes.py build_out12X/cmd_pure.exe
"""
import sys
import shutil

def patch_chkstk_sizes(path):
    # Read binary
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    
    # Find PE header and .text section
    pe_off = int.from_bytes(data[0x3C:0x40], 'little')
    num_sec = int.from_bytes(data[pe_off+6:pe_off+8], 'little')
    opt_hdr_size = int.from_bytes(data[pe_off+20:pe_off+22], 'little')
    sec_table = pe_off + 24 + opt_hdr_size
    
    text_raw_off = None
    text_raw_size = None
    text_rva = None
    for i in range(num_sec):
        off = sec_table + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode()
        if '.text' in name:
            text_rva = int.from_bytes(data[off+12:off+16], 'little')
            text_raw_size = int.from_bytes(data[off+16:off+20], 'little')
            text_raw_off = int.from_bytes(data[off+20:off+24], 'little')
            break
    
    if text_raw_off is None:
        print("ERROR: .text section not found")
        return 0
    
    text_data = data[text_raw_off:text_raw_off + text_raw_size]
    
    # Find _chkstk entry signature
    sigs = [
        bytes.fromhex('3d0010000051488d4c2410'),  # cmp eax,0x1000; push rcx; lea rcx,[rsp+0x10]
        bytes.fromhex('513d00100000488d4c2410'),  # push rcx; cmp eax,0x1000; lea rcx,[rsp+0x10]
        bytes.fromhex('3d0010000051488d4c2408'),  # cmp; push; lea rcx,[rsp+8]
        bytes.fromhex('513d00100000488d4c2408'),  # push; cmp; lea rcx,[rsp+8]
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
    # Scan for E8 calls to _chkstk
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
            # 7-byte REX.W: 48 C7 C0 imm32
            if scan + 7 <= call_pos:
                if (text_data[scan] == 0x48 and text_data[scan + 1] == 0xC7
                        and (text_data[scan + 2] & 0xF8) == 0xC0):
                    mov_imm_off = scan + 3
                    break
            # 5-byte B8: B8 imm32 (not preceded by REX 48)
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
        print(f"  PATCH 0x{file_off:X}: mov rax, {old_val:#x} -> {new_val:#x} (call at .text+0x{call_pos:X})")
        data[file_off:file_off + 4] = new_val.to_bytes(4, 'little')
        fixed += 1
    
    if fixed > 0:
        backup = path + '.bak'
        shutil.copy(path, backup)
        with open(path, 'wb') as f:
            f.write(data)
        print(f"Wrote {fixed} patches (backup at {backup})")
    else:
        print("No patches needed")
    
    return fixed

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'build_out122/cmd_pure.exe'
    patch_chkstk_sizes(path)
