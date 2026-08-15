import struct
from pathlib import Path

def pe_secs(data):
    e = struct.unpack_from("<I", data, 0x3c)[0]
    magic = struct.unpack_from("<H", data, e+24)[0]
    num = struct.unpack_from("<H", data, e+6)[0]
    soh = struct.unpack_from("<H", data, e+20)[0]
    sec = e+24+soh
    if magic==0x20b: # PE32+
        base = struct.unpack_from("<Q", data, e+24+24)[0]
        dd0 = e+24+112
    else:
        base = struct.unpack_from("<I", data, e+24+28)[0]
        dd0 = e+24+96
    secs=[]
    for i in range(num):
        o=sec+i*40
        name=data[o:o+8].split(b"\x00")[0].decode()
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        secs.append((name,va,vs,rs,rp))
    return base, secs

for label, path in [
    ("src", r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"),
    ("univ14", r"build_univ14\cmd_pure.exe"),
]:
    p=Path(path)
    if not p.exists():
        print(label, "MISSING"); continue
    data=p.read_bytes()
    base, secs = pe_secs(data)
    print(f"\n=== {label} base={base:#x} ===")
    for s in secs:
        print(f"  {s}")
    # find .data and read at offset 0x8d8 from original .data concept
    # In univ14 .data may be at different RVA; use rva map if present
    data_sec = next((s for s in secs if s[0]==".data"), None)
    if data_sec:
        name,va,vs,rs,rp=data_sec
        # original RVA 0x1c8d8 -> offset 0x8d8 into .data
        off=0x8d8
        if off < rs:
            raw=data[rp+off:rp+off+16]
            print(f"  .data+0x8d8 raw={raw.hex()} q0={struct.unpack_from('<Q' if base>0xffffffff else '<I', raw)[0]:#x}")
        else:
            print(f"  .data+0x8d8 beyond raw rs={rs:#x}")
        # also show first 32 bytes of .data
        print(f"  .data start={data[rp:rp+32].hex()}")

# rva map
rm=Path("build_univ14/rva.txt")
if rm.exists():
    print("\n=== rva map hits for 1c8d8 / c8d8 / data ===")
    for line in rm.read_text(errors="replace").splitlines():
        if any(x in line.lower() for x in ("1c8d8","c8d8","1c000",".data","24320")):
            print(" ", line[:120])
