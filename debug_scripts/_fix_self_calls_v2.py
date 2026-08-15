#!/usr/bin/env python3
"""
Post-build fix: Re-point self-calling E8 instructions inside align wrappers
to skip to the body (after the epilogue). This avoids infinite recursion
while preserving the stack alignment prologue/epilogue.

The fix: change E8 rel32 from pointing to prologue to pointing to body.
Body starts at prologue + 13 (prologue) + 5 (call) + 5 (epilogue) = prologue + 23.
So new rel32 = (prologue + 23) - (call_addr + 5) = (prologue + 23) - (prologue + 13 + 5) = 23 - 18 = 5.
"""
import pefile, struct, sys, shutil

def fix_self_calls(pe_path: str, backup: bool = True) -> int:
    if backup:
        shutil.copy2(pe_path, pe_path + ".bak")
    
    pe = pefile.PE(pe_path)
    
    AW_PROLOGUE = bytes([0x41, 0x55, 0x49, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xE4, 0xF0])
    AW_EPILOGUE = bytes([0x4C, 0x89, 0xEC, 0x41, 0x5D])
    PROLOGUE_LEN = len(AW_PROLOGUE)  # 13
    EPILOGUE_LEN = len(AW_EPILOGUE)  # 5
    CALL_LEN = 5
    
    BODY_OFFSET = PROLOGUE_LEN + CALL_LEN + EPILOGUE_LEN  # 23
    
    text_section = pe.sections[0]
    text_rva = text_section.VirtualAddress
    text_data = bytearray(pe.get_data(text_rva, text_section.Misc_VirtualSize))
    
    fixed = 0
    pos = 0
    while pos < len(text_data) - PROLOGUE_LEN - 5 - EPILOGUE_LEN:
        if text_data[pos:pos + PROLOGUE_LEN] != AW_PROLOGUE:
            pos += 1
            continue
        
        j = pos + PROLOGUE_LEN  # E8 position
        if j + 5 > len(text_data) or text_data[j] != 0xE8:
            pos += 1
            continue
        
        epi_pos = j + 5
        if epi_pos + EPILOGUE_LEN > len(text_data):
            pos += 1
            continue
        if text_data[epi_pos:epi_pos + EPILOGUE_LEN] != AW_EPILOGUE:
            pos += 1
            continue
        
        rel32 = struct.unpack_from('<i', text_data, j + 1)[0]
        target = j + 5 + rel32
        if target != pos:
            pos += 1
            continue
        
        # Self-call! Fix by pointing to body (after epilogue)
        new_target = pos + BODY_OFFSET
        new_rel32 = new_target - (j + 5)
        
        rva = text_rva + j
        print(f"  Fixing self-call at RVA 0x{rva:X}: rel32 {rel32} -> {new_rel32}")
        struct.pack_into('<i', text_data, j + 1, new_rel32)
        fixed += 1
        pos = epi_pos + EPILOGUE_LEN
    
    if fixed > 0:
        file_offset = text_section.PointerToRawData
        pe.set_bytes_at_offset(file_offset, bytes(text_data))
        pe.write(pe_path)
        print(f"Fixed {fixed} self-calling align wrappers in {pe_path}")
    else:
        print(f"No self-calling align wrappers found in {pe_path}")
    
    pe.close()
    return fixed

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'build_univ338/cmd_pure.exe'
    fix_self_calls(path)
