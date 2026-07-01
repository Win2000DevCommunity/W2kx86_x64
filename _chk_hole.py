"""Inspect main-tail hole and skip-reexec patch in cmd_shim."""
import struct
from pathlib import Path

shim = Path(__file__).resolve().parent.parent / "win2000_x64" / "cmd_shim.exe"
data = shim.read_bytes()

# PE parse minimal
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
opt = e_lfanew + 24
magic = struct.unpack_from("<H", data, opt)[0]
if magic == 0x20B:
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = opt + opt_sz
else:
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = opt + opt_sz

text_rva = None
for i in range(num_sec):
    o = sec_off + i * 40
    name = data[o : o + 8].split(b"\x00")[0]
    if name == b".text":
        text_rva = struct.unpack_from("<I", data, o + 12)[0]
        text_raw = struct.unpack_from("<I", data, o + 20)[0]
        break

def rva_off(rva):
    return text_raw + (rva - text_rva)

checks = [
    ("skip-reexec 0x8D83", 0x8D83, 0x8E08),
    ("main-tail hole 0x3FDA0", 0x3FDA0, 0x3FDA0 + 64),
    ("partial tail 0x3FD62", 0x3FD62, 0x3FD9D + 8),
]

for label, start, end in checks:
    off = rva_off(start)
    chunk = data[off : rva_off(end)]
    print(f"\n{label} (file+0x{off:X}):")
    for i in range(0, min(len(chunk), 128), 16):
        hexs = " ".join(f"{b:02x}" for b in chunk[i : i + 16])
        print(f"  +{start + i:05X}: {hexs}")

# check sentinel
h = rva_off(0x3FDA0)
print(f"\n0x3FDA0 first 4 bytes: {data[h:h+4].hex()} (expect != ffffffff if fixed)")
