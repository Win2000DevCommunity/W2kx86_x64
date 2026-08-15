import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from tools.audit_calls import read_text_section, load_map

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]; soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
for i in range(num):
    o = sec+i*40
    if src[o:o+5] == b".text":
        va, rs, rp = struct.unpack_from("<III", src, o+12)
        text = src[rp:rp+rs]; text_rva = va; break
base = struct.unpack_from("<I", src, e+24+28)[0]
md = Cs(CS_ARCH_X86, CS_MODE_32)

print("=== around 0xa330 (stores near c8d8) ===")
for insn in md.disasm(text[0xa320-text_rva:0xa420-text_rva], base+0xa320, count=50):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")

# Search for GetCommandLine
# IAT slot for GetCommandLineW/A
print("\n=== Find GetCommandLine refs ===")
# Search string in binary
for s in (b"GetCommandLineW", b"GetCommandLineA", b"GetCommandLine"):
    idx = src.find(s)
    print(s, "at", idx)

# Disasm main-ish entry and look for cmdline setup
# From earlier, entry related. Search call to GetCommandLine via IAT
# Common: call [iat]; mov [global], eax
needle_patterns = []
# Look for mov [0x4ad1c8d8] via A3 encoding (mov [imm], eax)
a3 = b"\xa3" + struct.pack("<I", 0x4ad1c8d8)
print("A3 store", text.find(a3))
# mov [imm], esi/edi etc - rare

# Maybe c8d8 is filled by wcscpy into a buffer whose ADDRESS is stored elsewhere,
# and c8d8 IS the buffer (not a pointer)? 
# Check: code does mov eax, [c8d8]; mov cx, [eax] - so c8d8 holds a POINTER
# (dereference then read word). Confirmed pointer.

# Search relocs targeting c8d8 - maybe init from reloc
print("\n=== Check if any code does lea/mov of address c8d8 into reg then store through it ===")
# mov reg, imm32 = B8+r
for r in range(8):
    pat = bytes([0xB8+r]) + struct.pack("<I", 0x4ad1c8d8)
    i = 0
    while True:
        j = text.find(pat, i)
        if j < 0: break
        print(f"  mov r{r}, c8d8 at {text_rva+j:#x}")
        i = j+1

# push c8d8 as address (push imm = 68)
pat = b"\x68" + struct.pack("<I", 0x4ad1c8d8)
i = 0
while True:
    j = text.find(pat, i)
    if j < 0: break
    print(f"  push c8d8 at {text_rva+j:#x}")
    for insn in md.disasm(text[j:j+20], base+text_rva+j, count=6):
        print(f"    {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
    i = j+1
