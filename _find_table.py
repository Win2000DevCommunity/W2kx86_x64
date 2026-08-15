import struct, pathlib
p=pathlib.Path("build_univ230/cmd_fix22.exe").read_bytes()
e=struct.unpack_from("<I",p,0x3C)[0]
ns=struct.unpack_from("<H",p,e+6)[0]; so=struct.unpack_from("<H",p,e+20)[0]; sec=e+24+so
S=[]
for i in range(ns):
    o=sec+i*40
    nm=p[o:o+8].split(b"\0")[0].decode(errors="replace")
    vs,va,rs,rp=struct.unpack_from("<IIII",p,o+8)
    S.append((nm,va,vs,rp,rs)); print(f"  sec {nm:8s} va={va:#x} vs={vs:#x} rp={rp:#x} rs={rs:#x}")
def o2r(o):
    for nm,va,vs,rp,rs in S:
        if rp<=o<rp+rs: return va+(o-rp)
def r2o(rva):
    for nm,va,vs,rp,rs in S:
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
targ="DIR\0".encode("utf-16-le")
hits=[o2r(i) for i in range(len(p)-len(targ)) if p[i:i+len(targ)]==targ]
print("DIR string RVAs:", [hex(h) for h in hits if h])
for h in hits:
    if not h: continue
    ptr=struct.pack("<I", 0x80000000+h)
    refs=[o2r(i) for i in range(len(p)-4) if p[i:i+4]==ptr]
    refs=[r for r in refs if r]
    print(f"  refs to {h:#x}:", [hex(r) for r in refs][:10])
