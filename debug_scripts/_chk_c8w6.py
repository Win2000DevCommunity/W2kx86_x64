import struct
from pathlib import Path

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]; soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
base = struct.unpack_from("<I", src, e+24+28)[0]
c8_rva = 0x4ad1c8d8 - base
print("base", hex(base), "c8 rva", hex(c8_rva))
for i in range(num):
    o = sec+i*40
    name = src[o:o+8].split(b"\0")[0].decode("ascii", "replace")
    va, vsz, rs, rp = struct.unpack_from("<IIII", src, o+8)
    chars = struct.unpack_from("<I", src, o+36)[0]
    print(f"  {name:8s} va={va:#08x} vsz={vsz:#x} rs={rs:#x} rp={rp:#x}")
    if va <= c8_rva < va + vsz:
        off = c8_rva - va
        if off < rs:
            val = struct.unpack_from("<I", src, rp+off)[0]
            print(f"    -> file contains dword {val:#x}")
            print(f"    -> surrounding: {src[rp+off-8:rp+off+16].hex()}")
        else:
            print(f"    -> BSS (beyond raw size), init 0")
