import struct, pathlib
pe = pathlib.Path("build_univ229/cmd_diam.exe").read_bytes()
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    name=pe[o:o+8].split(b"\0")[0]
    vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8)
    if name==b".data":
        # VA 0x80058628 -> file
        off = rp + (0x58628 - va)
        chunk = pe[off:off+64]
        print("58628", chunk.decode("utf-16-le", errors="replace")[:40], chunk.hex())
    if name==b".rdata" or name.startswith(b".r"):
        pass
# also check 800479fc
for i in range(ns):
    o = sec+i*40
    name=pe[o:o+8].split(b"\0")[0]
    vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8)
    if va <= 0x479fc < va+rs:
        off = rp + (0x479fc - va)
        chunk = pe[off:off+80]
        print(name, "479fc", chunk[:40].decode("ascii", errors="replace"), chunk[:40].hex())
