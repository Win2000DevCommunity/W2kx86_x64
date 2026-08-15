import struct
from pathlib import Path

# Simulate: what happens if QWORD widening at overlapping sites destroys c8d8
src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]; soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
base = struct.unpack_from("<I", src, e+24+28)[0]
img_size = struct.unpack_from("<I", src, e+24+56)[0]
for i in range(num):
    o=sec+i*40
    name=src[o:o+8].split(b"\x00")[0].decode()
    vs,va,rs,rp=struct.unpack_from("<IIII", src, o+8)
    if name==".data":
        raw=src[rp:rp+rs]+b"\x00"*(vs-rs)
        print("len raw", len(raw), "vs", vs)
        # dump 0x8c0-0x900
        print("before", raw[0x8c0:0x900].hex())
        # find all image-looking dwords in first 0x1000
        old_base=base; img_end=base+img_size
        sites=[]
        for off in range(0, min(len(raw),0x1000)-3, 4):
            val=struct.unpack_from("<I", raw, off)[0]
            if old_base <= val < img_end or (0 < val < img_size and val>=0x1000):
                sites.append((off,val))
            elif 0 < val < 0x100:  # small - would current code catch?
                if 0 < val < img_size:
                    sites.append((off,val))  # YES current code catches ALL 0<val<image_size
        print(f"pointer-like sites in raw .data first 4k: {len(sites)}")
        # show sites that would overlap 0x8d8 when written as QWORD
        for off,val in sites:
            if off <= 0x8d8 < off+8 or off < 0x8d8+4 <= off+8 or (0x8d8<=off<0x8d8+8):
                print(f"  overlap/self off={off:#x} val={val:#x}")
        # specifically show 0x8d0-0x8f0 sites
        for off,val in sites:
            if 0x8c0 <= off <= 0x8f0:
                print(f"  site {off:#x}: {val:#x}")
