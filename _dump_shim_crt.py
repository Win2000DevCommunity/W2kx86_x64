import struct
from pathlib import Path

shim = Path(__file__).resolve().parent.parent / "win2000_x64" / "cmd_shim.exe"
data = shim.read_bytes()
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
opt = e_lfanew + 24
num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
opt_sz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
sec_off = opt + opt_sz
image_base = struct.unpack_from("<Q", data, opt + 24)[0]
for i in range(num_sec):
    o = sec_off + i * 40
    if data[o:o+5] == b".text":
        text_rva = struct.unpack_from("<I", data, o + 12)[0]
        text_raw = struct.unpack_from("<I", data, o + 20)[0]
        break

def dump(rva, n=64):
    off = text_raw + (rva - text_rva)
    chunk = data[off:off+n]
    print(f"\nshim .text+0x{rva:X} (VA 0x{image_base+rva:X}):")
    for i in range(0, len(chunk), 16):
        hexs = " ".join(f"{b:02x}" for b in chunk[i:i+16])
        print(f"  +{rva+i:05X}: {hexs}")

for rva in (0x2D980, 0x2D9A0, 0x2D9A6, 0x2D9B0, 0x2DCC0, 0x2E042, 0x8D83, 0x8E08, 0x8E28):
    dump(rva)
