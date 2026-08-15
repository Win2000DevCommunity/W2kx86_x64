"""Check crash site x86 origin - extended analysis."""
import pefile
import struct
import capstone

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
pure_pe = pefile.PE('build_out90/cmd_pure.exe')

# ============================================================
# 1. Which section is the crash site in?
# ============================================================
crash_pure = 0x43CF5
caller_pure = 0x14AE1
print("=== Pure PE Sections ===")
for s in pure_pe.sections:
    name = s.Name.rstrip(b'\x00').decode()
    exec_flag = "X" if s.Characteristics & 0x20000000 else "-"
    print(f"  {name}: RVA=0x{s.VirtualAddress:06X} VSize=0x{s.Misc_VirtualSize:06X} [{exec_flag}]")

for s in pure_pe.sections:
    if s.VirtualAddress <= crash_pure < s.VirtualAddress + s.Misc_VirtualSize:
        name = s.Name.rstrip(b'\x00').decode()
        off = crash_pure - s.VirtualAddress
        is_exec = bool(s.Characteristics & 0x20000000)
        print(f"\nCrash 0x{crash_pure:X} is in section '{name}' (offset 0x{off:X}), executable={is_exec}")
        if not is_exec:
            print("  *** CRASH IS IN NON-EXECUTABLE SECTION! ***")

# ============================================================
# 2. Check pure binary disassembly around crash
# ============================================================
print(f"\n=== x64 disasm around crash site 0x{crash_pure:X} ===")
text_pure = next(s for s in pure_pe.sections if s.Name.rstrip(b'\x00') == b'.text')
text_rva_pure = text_pure.VirtualAddress
data_pure = text_pure.get_data()
off = crash_pure - text_rva_pure
md64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md64.detail = True
try:
    for insn in md64.disasm(data_pure[max(0,off-16):off+48], 0x80000000 + crash_pure - 16):
        marker = '>>' if insn.address == 0x80000000 + crash_pure else '  '
        print(f"  {marker} 0x{insn.address:X}: {insn.mnemonic:10s} {insn.op_str}")
except Exception as e:
    print(f"  Disasm error: {e}")

# ============================================================
# 3. Check ALL calls in the pure binary that target near crash site
# ============================================================
print(f"\n=== Scanning for call/jmp targets near 0x{crash_pure:X} ===")
for i in range(len(data_pure) - 5):
    if data_pure[i] == 0xE8:
        rel = struct.unpack_from('<i', data_pure, i+1)[0]
        tgt = text_rva_pure + i + 5 + rel
        if abs(tgt - crash_pure) < 0x2000:
            print(f"  E8 at pure 0x{text_rva_pure+i:X}: rel={rel:+d} target=0x{tgt:X}")
    elif data_pure[i] == 0xE9:
        rel = struct.unpack_from('<i', data_pure, i+1)[0]
        tgt = text_rva_pure + i + 5 + rel
        if abs(tgt - crash_pure) < 0x2000:
            print(f"  E9 at pure 0x{text_rva_pure+i:X}: rel={rel:+d} target=0x{tgt:X}")

# ============================================================
# 4. Check what the x86 .data section bytes look like at x86 0x26C2B
# ============================================================
print(f"\n=== x86 original .data section at x86 0x26C2B ===")
x86_caller = 0x26C2B
for s in pe.sections:
    if s.VirtualAddress <= x86_caller < s.VirtualAddress + s.Misc_VirtualSize:
        name = s.Name.rstrip(b'\x00').decode()
        off = x86_caller - s.VirtualAddress
        raw_sz = s.SizeOfRawData
        print(f"  Section '{name}': RVA=0x{s.VirtualAddress:X}, RawSize=0x{raw_sz:X}, VSize=0x{s.Misc_VirtualSize:X}")
        print(f"  Offset into section: 0x{off:X}")
        if off < raw_sz:
            data = s.get_data()
            raw = data[off:off+32]
            for i in range(0, len(raw), 16):
                chunk = raw[i:i+16]
                hex_str = ' '.join(f'{b:02X}' for b in chunk)
                print(f"    0x{x86_caller+i:05X}: {hex_str}")
        else:
            print(f"  *** Beyond RawSize - would be zero-initialized BSS at runtime ***")
            print(f"  *** The translator should NOT be generating code from .bss! ***")
        break
