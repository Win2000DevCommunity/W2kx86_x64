import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

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
# C7 05 c8d8... = mov dword [abs], imm
# 89 05 / A3 = mov [abs], eax
patterns = [
    (b"\xc7\x05" + struct.pack("<I", 0x4ad1c8d8), "mov [c8d8], imm"),
    (b"\x89\x05" + struct.pack("<I", 0x4ad1c8d8), "mov [c8d8], eax"),
    (b"\xa3" + struct.pack("<I", 0x4ad1c8d8), "mov [c8d8], eax abs"),
    (b"\x89\x0d" + struct.pack("<I", 0x4ad1c8d8), "mov [c8d8], ecx"),
    (b"\x89\x15" + struct.pack("<I", 0x4ad1c8d8), "mov [c8d8], edx"),
    (b"\x89\x1d" + struct.pack("<I", 0x4ad1c8d8), "mov [c8d8], ebx"),
    (b"\x89\x35" + struct.pack("<I", 0x4ad1c8d8), "mov [c8d8], esi"),
    (b"\x89\x3d" + struct.pack("<I", 0x4ad1c8d8), "mov [c8d8], edi"),
]
for pat, name in patterns:
    pos = 0
    while True:
        i = text.find(pat, pos)
        if i < 0: break
        print(f"{name} at {text_rva+i:#x}")
        pos = i+1

# Also search whole image data for init
data_all = src
print("in full file as reloc target etc - check .data init")
# find which section contains rva of c8d8-base
c8_rva = 0x4ad1c8d8 - base
print("c8d8 rva", hex(c8_rva))
for i in range(num):
    o = sec+i*40
    name = src[o:o+8].split(b"\0")[0]
    va, vsz, rs, rp = struct.unpack_from("<IIII", src, o+8)
    if va <= c8_rva < va + max(vsz, rs):
        off = rp + (c8_rva - va)
        val = struct.unpack_from("<I", src, off)[0]
        print(f"  in {name} fileoff={off:#x} init_val={val:#x}")
