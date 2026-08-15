#!/usr/bin/env python3
"""Find x86 source of the self-calling wrapper by matching the body pattern."""
import pefile, capstone, re, struct

pe = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
base = pe.OPTIONAL_HEADER.ImageBase  # 0x4AD00000
text_rva = 0x1000
text_size = 0x1AE00
text_data = pe.get_data(text_rva, text_size)

md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

# Search for: and [ebp-8], 0; mov eax, <imm32>; mov byte [eax], 1
# Pattern: 83 65 F8 00 B8 ?? ?? ?? ?? C6 00 01
# But we need to be flexible about the registers

# Actually, the x64 body starts with: and [rbp-8], 0; movabs rax, <imm64>; mov byte [rax], 1
# The imm64 is 0x800494B0. What x86 VA does this correspond to?
# x64 VA 0x800494B0 -> x64 RVA 0x494B0
# The translator maps x86 addresses to x64 addresses. x86 VA like 0x4AD0XXXX gets mapped to x64 VA 0x8004XXXX.
# So 0x800494B0 might correspond to x86 VA 0x4AD094B0? But that's way beyond the x86 image.
# Or maybe it's x86 VA 0x4AD004B0? Still beyond.
# 
# Wait - the x64 .text is at RVA 0x1000, and the data referenced (0x494B0) is also in .text.
# In the x86 binary, .text is at RVA 0x1000.
# If the translator maps x86 RVA X to x64 RVA roughly scale_factor * X... but the scale isn't uniform.

# Let me try a different approach: search for specific byte patterns in x86 that match the x64 body

# The x64 body does:
# 83 65 F8 00          and [rbp-8], 0
# 48 B8 B0 94 04 80 00 00 00 00  movabs rax, 0x800494B0
# C6 00 01             mov byte [rax], 1
# 48 8D 45 C0          lea rax, [rbp-0x40]
# 49 BB 98 94 04 80 00 00 00 00  movabs r11, 0x80049498
# 41 89 03             mov [r11], eax

# The x86 equivalent would be something like:
# 83 65 F8 00          and [ebp-8], 0
# B8 ?? ?? ?? ??       mov eax, <imm32>
# C6 00 01             mov byte [eax], 1
# 8D 45 C0             lea eax, [ebp-0x40]
# A3 ?? ?? ?? ??       mov [<abs32>], eax

# Let's search for: 83 65 F8 00 ?? C6 00 01 8D 45 C0
# The ?? between 00 and C6 could be mov eax, imm32 (B8 xx xx xx xx)

# Actually let me just search for 83 65 F8 00 (and [ebp-8], 0)
print("=== Searching for 'and [ebp-8], 0' in x86 with context ===")
pat = bytes([0x83, 0x65, 0xF8, 0x00])
matches = []
for m in re.finditer(pat, text_data):
    off = m.start()
    x86_rva = text_rva + off
    # Get context before and after
    ctx_start = max(0, off - 5)
    ctx_end = min(len(text_data), off + 50)
    ctx = text_data[ctx_start:ctx_end]
    matches.append((x86_rva, ctx))
    
print(f"Found {len(matches)} matches")
for x86_rva, ctx in matches:
    print(f"\n--- x86 RVA 0x{x86_rva:X} (VA 0x{base + x86_rva:X}) ---")
    for insn in md32.disasm(ctx, base + text_rva + max(0, list(re.finditer(pat, text_data))[0].start() - 5)):
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
    print(f"  Raw bytes: {ctx[:32].hex(' ')}")

# Let me also directly search for the x86 pattern that would produce:
# and [ebp-8], 0; mov eax, <global_ptr>; mov byte [eax], 1
# This is a common CRT pattern for setting a flag
print("\n=== Searching for 'mov byte [eax], 1' near 'and [ebp-8], 0' ===")
pat2 = bytes([0xC6, 0x00, 0x01])  # mov byte [eax], 1
for m in re.finditer(pat2, text_data):
    off = m.start()
    x86_rva = text_rva + off
    # Check if preceded by 'and [ebp-8], 0' within ~30 bytes
    ctx_start = max(0, off - 30)
    ctx = text_data[ctx_start:off+10]
    if pat in ctx:
        print(f"  x86 RVA 0x{x86_rva:X}: context matches!")
        for insn in md32.disasm(ctx, base + text_rva + ctx_start):
            marker = " <--" if insn.address == base + x86_rva else ""
            print(f"    0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{marker}")
