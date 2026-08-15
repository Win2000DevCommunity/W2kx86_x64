import struct, pathlib
x=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
def secs(b):
    e=struct.unpack_from("<I",b,0x3C)[0]
    ns=struct.unpack_from("<H",b,e+6)[0]; so=struct.unpack_from("<H",b,e+20)[0]; sec=e+24+so
    out=[]
    for i in range(ns):
        o=sec+i*40
        nm=b[o:o+8].split(b"\0")[0].decode(errors="replace")
        vs,va,rs,rp=struct.unpack_from("<IIII",b,o+8)
        out.append((nm,va,vs,rp,rs))
    return out
def r2o(b,rva):
    for nm,va,vs,rp,rs in secs(b):
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
xo=r2o(x,0x1c8e0)
print("x86 table @0x1c8e0 (5 entries of 0x18):")
for i in range(5):
    row=x[xo+i*0x18:xo+(i+1)*0x18]
    ptr=struct.unpack_from("<I",row,0)[0]
    so_=r2o(x,ptr-0x4ad00000) if ptr>0x4ad00000 else None
    nm=""
    if so_: nm=x[so_:so_+30].decode("utf-16-le","replace").split("\0")[0]
    print(f"  [{i}] {row.hex()}  name={ptr:#x} '{nm}'")
p=pathlib.Path("build_univ230/cmd_fix22.exe").read_bytes()
print("pe64 data @0x47cdc (6 entries of 0x18):")
po=r2o(p,0x47cdc)
for i in range(6):
    row=p[po+i*0x18:po+(i+1)*0x18]
    ptr=struct.unpack_from("<I",row,0)[0]
    nm=""
    o2=r2o(p,ptr-0x80000000) if 0x80000000<=ptr<0x80100000 else None
    if o2: nm=p[o2:o2+30].decode("utf-16-le","replace").split("\0")[0]
    print(f"  [{i}] {row.hex()}  name={ptr:#x} '{nm}'")
print("pe64 raw 0x47cb0..0x47d60:")
po=r2o(p,0x47cb0)
print(" ", p[po:po+0xb0].hex())
