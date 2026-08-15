import struct
from pathlib import Path

def pe_secs(data):
    e = struct.unpack_from("<I", data, 0x3c)[0]
    magic = struct.unpack_from("<H", data, e+24)[0]
    num = struct.unpack_from("<H", data, e+6)[0]
    soh = struct.unpack_from("<H", data, e+20)[0]
    sec = e+24+soh
    if magic==0x20b:
        base = struct.unpack_from("<Q", data, e+24+24)[0]
    else:
        base = struct.unpack_from("<I", data, e+24+28)[0]
    secs=[]
    for i in range(num):
        o=sec+i*40
        name=data[o:o+8].split(b"\x00")[0].decode()
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        secs.append((name,va,vs,rs,rp))
    return base, secs

for label, path in [("univ14","build_univ14/cmd_pure.exe"),("univ15","build_univ15/cmd_pure.exe")]:
    p=Path(path)
    if not p.exists():
        print(label, "missing"); continue
    data=p.read_bytes()
    base, secs = pe_secs(data)
    ds=next(s for s in secs if s[0]==".data")
    name,va,vs,rs,rp=ds
    print("%s base=%#x .dataVA=%#x" % (label, base, va))
    print("  +0x8d0:", data[rp+0x8d0:rp+0x8f0].hex())
    print("  q@8d8=%#x" % struct.unpack_from("<Q", data, rp+0x8d8)[0])
    print("  d@8e0=%#x" % struct.unpack_from("<I", data, rp+0x8e0)[0])
    print("  d@8e4=%#x" % struct.unpack_from("<I", data, rp+0x8e4)[0])
