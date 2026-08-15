#!/usr/bin/env python3
"""Check globals referenced by the self-calling wrapper."""
import pefile, struct

pe = pefile.PE("build_univ337/cmd_pure.exe")
base = pe.OPTIONAL_HEADER.ImageBase  # 0x80000000

for rva in [0x494B0, 0x49498, 0x494A0]:
    for s in pe.sections:
        name = s.Name.decode('utf-8','ignore').rstrip('\x00')
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            offset = rva - s.VirtualAddress
            data = pe.get_data(rva, 16)
            val64 = struct.unpack_from('<Q', data, 0)[0] if len(data) >= 8 else 0
            val32 = struct.unpack_from('<I', data, 0)[0] if len(data) >= 4 else 0
            print(f"RVA 0x{rva:X} in {name} at +0x{offset:X}: raw={data[:16].hex(' ')}")
            print(f"  qword=0x{val64:X} dword=0x{val32:X}")
            break
    else:
        print(f"RVA 0x{rva:X}: NOT FOUND in any section")

# Also check: what x86 function maps to x64 0x4CF32?
# We know the x64 wrapper body does: and [rbp-8],0; movabs rax, <global0>; mov byte [rax],1; ...
# Let me find all x86 functions that produce similar x64 code.
# Actually, let me search the rva_map if it's available.
print("\n=== Checking for rva_map logs ===")
import os
for f in os.listdir("build_univ337"):
    if "map" in f.lower() or "rva" in f.lower():
        print(f"  Found: {f}")

# Let's look at the alignment wrapper more carefully.
# The wrapper is: push r13; mov r13,rsp; sub rsp,0x20; and rsp,-0x10; call XXX; mov rsp,r13; pop r13
# This is the standard "aligned call" pattern emitted by _emit_call_align_prologue + call + _emit_call_align_epilogue
# But the call target is wrong.
# 
# Question: is the body (after the epilogue) a separate function, or is it part of the same function?
# Looking at the code flow: after the epilogue, the body starts. The body does NOT have its own prologue.
# This suggests the wrapper+body is a single entity: the wrapper handles stack alignment, then falls into the body.
# But the call at the end of the wrapper should go to the body, not back to the wrapper.
# This is clearly a bug where the call target is calculated relative to something wrong.

# Let me check: what if the wrapper and body are from DIFFERENT functions?
# The body at 0x4CF49 does:
#   and [rbp-8], 0       ; uses rbp!
# But the wrapper sets r13 as frame pointer, not rbp. So the body expects rbp to already be set.
# This means the wrapper and body belong to the SAME function - the body expects rbp to be the frame pointer,
# and the wrapper preserves r13. So rbp is the function's frame pointer, set by the outer function.

# Wait, this doesn't make sense. Let me think again...
# The function entry is at 0x4CF32. The code is:
# 0x4CF32: push r13           ; save caller's r13
# 0x4CF34: mov r13, rsp        ; r13 = current stack pointer (for alignment)
# 0x4CF37: sub rsp, 0x20       ; allocate shadow space
# 0x4CF3B: and rsp, -0x10      ; align stack to 16
# 0x4CF3F: call 0x8004cf32     ; call self! WRONG!
# 0x4CF44: mov rsp, r13        ; restore stack
# 0x4CF47: pop r13              ; restore r13
# 0x4CF49: and [rbp-8], 0      ; body
# ...
# 
# Actually wait - this is NOT a standard function entry. This is a THUNK that wraps a call.
# The thunk sets up alignment, calls the real body, then restores.
# But the call targets the thunk itself instead of the body!
# 
# What if the thunk is wrapping a call that's supposed to be a self-recursive call?
# No, that makes no sense - infinite recursion.
# 
# Let me look at the original x86 code at whatever function this corresponds to.
# I need to find the x86->x64 mapping.

# Approach: search for the pattern in the x64 binary and correlate with x86.
# The x64 body starts with: and [rbp-8],0 -> 83 65 F8 00
# In x86: and [ebp-8],0 -> 83 65 F8 00
# Let me look at the x86 functions that contain this pattern and whose x64 translation 
# includes an align wrapper.

# Actually, let me just check: does the x64 binary have many such wrappers?
# Count all instances of the pattern: push r13; mov r13,rsp; sub rsp,0x20; and rsp,-0x10; E8 xx xx xx xx; mov rsp,r13; pop r13
print("\n=== Counting align-wrapper + call patterns in x64 binary ===")
import capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
text_data = pe.get_data(0x1000, pe.sections[0].Misc_VirtualSize)
base_va = base + 0x1000

# Search for the pattern byte-by-byte
import re
AW_PROLOGUE = bytes([0x41, 0x55, 0x49, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xE4, 0xF0])
AW_EPILOGUE = bytes([0x4C, 0x89, 0xEC, 0x41, 0x5D])

# Actually the prologue bytes I read before were: 41 55 49 89 E5 48 83 EC 20 48 83 E4 F0
# But Capstone decoded them differently. Let me check.
# push r13 = 41 55 (2 bytes)
# mov r13, rsp = 4C 89 ED? Let me check...
# Actually: 49 89 E5 with REX.WB prefix - in 64-bit: 
# 49 = REX.WB (W=0, R=0, X=0, B=1)
# 89 = MOV r/m64, r64
# E5 = mod=11, reg=100(rsp), rm=101(rbp/r13)
# With REX.B=1, rm=101 -> r13
# So 49 89 E5 = mov r13, rsp. Yes.

# But the bytes I read were: 41 55 49 89 E5 48 83 EC 20 48 83 E4 F0 E8 ...
# Let me verify against the disassembly output.
# Capstone said: 0x8004CF32: push r13 (41 55), 0x8004CF34: mov r13, rsp (49 89 E5)
# But earlier I found the bytes as: 41 55 49 89 E5 
# This is NOT 4C 89 ED. So the Capstone output shows the mnemonic as "mov r13, rsp" but the encoding is 49 89 E5.
# That's correct: 49 89 E5 = mov r13, rsp in 64-bit mode.

# Now the epilogue: mov rsp, r13 = 4C 89 EC? Or 49 89 E5 again but different?
# The bytes at 0x4CF44: 4C 89 EC = REX.WR + MOV + mod=11, reg=101(r13/rbp), rm=100(rsp)
# With REX.R=1, reg=101 -> r13. So 4C 89 EC = mov rsp, r13. Yes.

# So the full pattern is:
# 41 55                         push r13
# 49 89 E5                      mov r13, rsp
# 48 83 EC 20                   sub rsp, 0x20
# 48 83 E4 F0                   and rsp, -0x10
# E8 xx xx xx xx                call <target>
# 4C 89 EC                      mov rsp, r13
# 41 5D                         pop r13

# Let me search for this exact byte sequence (with wildcards for the call rel32)
pattern_start = bytes([0x41, 0x55, 0x49, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xE4, 0xF0, 0xE8])
epi = bytes([0x4C, 0x89, 0xEC, 0x41, 0x5D])

count = 0
self_calls = []
for m in re.finditer(pattern_start, text_data):
    start_off = m.start()
    call_off = start_off + 14  # E8 is at offset 14
    rel32 = struct.unpack_from('<i', text_data, call_off + 1)[0]
    target = call_off + 5 + rel32
    # Check if followed by epilogue
    epi_off = call_off + 5  # after the 5-byte call
    if epi_off + 5 <= len(text_data) and text_data[epi_off:epi_off+5] == epi:
        count += 1
        x64_rva = 0x1000 + start_off
        target_rva = 0x1000 + target
        is_self = (target == start_off)
        print(f"Wrapper at x64 RVA 0x{x64_rva:X}: call targets 0x{target_rva:X} self={is_self}")
        if is_self:
            self_calls.append(x64_rva)

print(f"Total wrappers: {count}, self-calls: {len(self_calls)}")
print(f"Self-call RVAs: {[hex(x) for x in self_calls]}")
