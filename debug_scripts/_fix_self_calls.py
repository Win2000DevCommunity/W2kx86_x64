#!/usr/bin/env python3
"""
Post-build fix: NOP out self-calling E8 instructions inside align wrappers.
These are align wrappers where the call targets the wrapper's own prologue,
creating infinite recursion. The call is replaced with NOPs so execution
falls through to the body.
"""
import pefile, struct, sys, shutil, os

def fix_self_calls(pe_path: str, backup: bool = True) -> int:
    if backup:
        shutil.copy2(pe_path, pe_path + ".bak")
    
    pe = pefile.PE(pe_path)
    
    # Align wrapper pattern:
    # push r13       = 41 55           (2 bytes)
    # mov r13, rsp   = 49 89 E5        (3 bytes)
    # sub rsp, 0x20  = 48 83 EC 20     (4 bytes)
    # and rsp, -0x10 = 48 83 E4 F0     (4 bytes)
    # E8 xx xx xx xx                    (5 bytes) <-- call (potentially self)
    # mov rsp, r13   = 4C 89 EC        (3 bytes)
    # pop r13        = 41 5D           (2 bytes)
    
    AW_PROLOGUE = bytes([0x41, 0x55, 0x49, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xE4, 0xF0])
    AW_EPILOGUE = bytes([0x4C, 0x89, 0xEC, 0x41, 0x5D])
    PROLOGUE_LEN = len(AW_PROLOGUE)  # 13
    EPILOGUE_LEN = len(AW_EPILOGUE)  # 5
    
    text_section = pe.sections[0]  # .text
    text_rva = text_section.VirtualAddress
    text_data = bytearray(pe.get_data(text_rva, text_section.Misc_VirtualSize))
    
    fixed = 0
    pos = 0
    while pos < len(text_data) - PROLOGUE_LEN - 5 - EPILOGUE_LEN:
        # Find prologue
        if text_data[pos:pos + PROLOGUE_LEN] != AW_PROLOGUE:
            pos += 1
            continue
        
        j = pos + PROLOGUE_LEN  # position of E8 (or other instruction)
        
        # Check for E8 (call)
        if j + 5 > len(text_data) or text_data[j] != 0xE8:
            pos += 1
            continue
        
        # Check for epilogue
        epi_pos = j + 5
        if epi_pos + EPILOGUE_LEN > len(text_data):
            pos += 1
            continue
        if text_data[epi_pos:epi_pos + EPILOGUE_LEN] != AW_EPILOGUE:
            pos += 1
            continue
        
        # Check if call targets the prologue (self-call)
        rel32 = struct.unpack_from('<i', text_data, j + 1)[0]
        target = j + 5 + rel32
        if target != pos:
            pos += 1
            continue
        
        # Self-call detected! NOP out the call instruction
        rva = text_rva + j
        print(f"  Fixing self-call at RVA 0x{rva:X}: E8 -> NOPs")
        text_data[j:j + 5] = b'\x90\x90\x90\x90\x90'
        fixed += 1
        pos = epi_pos + EPILOGUE_LEN  # Skip past the fixed wrapper
    
    if fixed > 0:
        # Write back to PE
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
