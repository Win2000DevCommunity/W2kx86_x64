import struct
from pathlib import Path

def pe_sects(path):
    raw = Path(path).read_bytes()
    e = struct.unpack_from("<I", raw, 0x3c)[0]
    magic = struct.unpack_from("<H", raw, e+24)[0]
    num = struct.unpack_from("<H", raw, e+6)[0]
    soh = struct.unpack_from("<H", raw, e+20)[0]
    sec = e+24+soh
    if magic == 0x20b:  # PE32+
        image_base = struct.unpack_from("<Q", raw, e+24+24)[0]
    else:
        image_base = struct.unpack_from("<I", raw, e+24+28)[0]
    print(f"=== {path} base={image_base:#x} ===")
    for i in range(num):
        o = sec+i*40
        name = raw[o:o+8].split(b"\0")[0].decode("ascii","replace")
        vsz, va, rs, rp = struct.unpack_from("<IIII", raw, o+8)
        print(f"  {name:8s} va={va:#08x} vsz={vsz:#x} rs={rs:#x}")
    return raw, image_base, sec, num

# Source
raw32, base32, sec, num = pe_sects(
    r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
c8_rva = 0x4ad1c8d8 - base32
print(f"c8d8 rva in src = {c8_rva:#x}")

# univ14
raw64, base64, sec64, num64 = pe_sects("build_univ14/cmd_pure.exe")
# Find which section contains the VA used in code: 0x8005c8d8
want = 0x8005c8d8 - base64
print(f"code uses c8d8 as VA 0x8005c8d8 -> rva {want:#x}")
for i in range(num64):
    o = sec64+i*40
    name = raw64[o:o+8].split(b"\0")[0].decode("ascii","replace")
    vsz, va, rs, rp = struct.unpack_from("<IIII", raw64, o+8)
    if va <= want < va + max(vsz, rs):
        off = want - va
        if off < rs:
            val = struct.unpack_from("<Q", raw64, rp+off)[0]
            print(f"  FOUND in {name} fileoff={rp+off:#x} qwords={val:#x}")
            print(f"  surrounding: {raw64[rp+off:rp+off+16].hex()}")
        else:
            print(f"  FOUND in {name} BSS (zero)")

# Also check if src rva 0x1c8d8 maps somewhere in new PE via rva_map or data layout
# How does translator relocate? Check _relocate_imm / section map
