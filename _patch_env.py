import struct
from pathlib import Path

src = Path("build_envfix/cmd_pure.exe")
dst = Path("build_envfix2/cmd_pure.exe")
dst.parent.mkdir(exist_ok=True)
blob = bytearray(src.read_bytes())

pe = struct.unpack_from("<I", blob, 0x3C)[0]
img = struct.unpack_from("<Q", blob, pe + 24 + 24)[0]
n = struct.unpack_from("<H", blob, pe + 6)[0]
opt = struct.unpack_from("<H", blob, pe + 20)[0]
sec = pe + 24 + opt
sections = []
for i in range(n):
    off = sec + i * 40
    name = blob[off:off+8].split(b"\x00")[0]
    vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", blob, off + 8)
    sections.append((name, vaddr, rptr, rsize))

def va_to_fo(va):
    rva = va - img
    for name, vaddr, rptr, rsize in sections:
        if vaddr <= rva < vaddr + rsize:
            return rptr + (rva - vaddr)
    raise KeyError(hex(va))

# 1) bump mov rbx, 0x800 -> 0x4000 at getenv (0x49021)
fo = va_to_fo(0x80049021)
assert blob[fo:fo+7] == bytes.fromhex("48c7c300080000"), blob[fo:fo+7].hex()
blob[fo:fo+7] = bytes.fromhex("48c7c300400000")
print("bumped getenv buffer size to 0x4000")

# 2) fix PATHEXT string: restore orig bytes from corruption
# orig: 500041005400480045005800540000002e0043004f004d00
fo = va_to_fo(0x8005c6a8)
corrupt = blob[fo:fo+24]
print("before PATHEXT", corrupt.hex())
blob[fo:fo+24] = bytes.fromhex("500041005400480045005800540000002e0043004f004d00")
print("after  PATHEXT", blob[fo:fo+24].hex())

# 3) fix .COM default at 0x8005c6b8 if needed
fo = va_to_fo(0x8005c6b8)
print("default before", blob[fo:fo+24].hex())
# orig starts with 2e0043004f004d003b002e004500580045003b002e004200
blob[fo:fo+24] = bytes.fromhex("2e0043004f004d003b002e004500580045003b002e004200")
print("default after ", blob[fo:fo+24].hex())

dst.write_bytes(blob)
shim = Path("build_envfix/w2kshim64.dll")
if shim.exists():
    (dst.parent / "w2kshim64.dll").write_bytes(shim.read_bytes())
print("wrote", dst)
