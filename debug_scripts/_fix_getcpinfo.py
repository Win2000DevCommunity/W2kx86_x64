#!/usr/bin/env python3
"""Post-build fix: repair the GetCPInfo guard and thunk."""
import pefile, struct, sys

pe = pefile.PE(sys.argv[1] if len(sys.argv) > 1 else 'build_univ340/cmd_pure.exe')

# Fix 1: Guard at 0x247B4 - change JE to JMP so it always calls GetCPInfo
rva = 0x247C2
file_off = rva - pe.sections[0].VirtualAddress + pe.sections[0].PointerToRawData
with open(sys.argv[1] if len(sys.argv) > 1 else 'build_univ340/cmd_pure.exe', 'r+b') as f:
    f.seek(file_off)
    f.write(b'\xEB\x09')  # jmp +9 instead of je +9
print("Fix 1: Guard at 0x247B4 now always calls GetCPInfo")

# Fix 2: Thunk at 0x21CF - the epilogue is incomplete (missing pop r13)
# After the guard returns, we need pop r13; ret
# At 0x21E1: 4C 89 EC = mov rsp, r13
# We need to overwrite the garbage at 0x21E4 with 41 5D C3 (pop r13; ret)
rva2 = 0x21E4
file_off2 = rva2 - pe.sections[0].VirtualAddress + pe.sections[0].PointerToRawData
with open(sys.argv[1] if len(sys.argv) > 1 else 'build_univ340/cmd_pure.exe', 'r+b') as f:
    f.seek(file_off2)
    f.write(b'\x41\x5D\xC3')  # pop r13; ret
print("Fix 2: Thunk epilogue repaired (pop r13; ret added)")

pe.close()
print("Done")
