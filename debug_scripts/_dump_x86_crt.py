"""Dump x86 cmd.exe bytes around CRT CreateProcess / 0x8D83 shim equivalent."""
import struct
from pathlib import Path

cmd = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
data = cmd.read_bytes()
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
opt = e_lfanew + 24
num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
opt_sz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
sec_off = opt + opt_sz
image_base = struct.unpack_from("<I", data, opt + 28)[0]
for i in range(num_sec):
    o = sec_off + i * 40
    if data[o:o+5] == b".text":
        text_rva = struct.unpack_from("<I", data, o + 12)[0]
        text_raw = struct.unpack_from("<I", data, o + 20)[0]
        break

def dump(rva, n=128):
    off = text_raw + (rva - text_rva)
    chunk = data[off:off+n]
    print(f"\nx86 .text+0x{rva:X} (VA 0x{image_base+rva:X}):")
    for i in range(0, len(chunk), 16):
        hexs = " ".join(f"{b:02x}" for b in chunk[i:i+16])
        print(f"  +{rva+i:05X}: {hexs}")

for rva in (0x8777, 0x8D70, 0x8D83, 0x8DEE, 0x8E00, 0x2D990, 0x2D9A6, 0x2E040, 0xDBB0, 0xDCEE, 0xDD9D, 0xDE90):
    dump(rva, 96)
