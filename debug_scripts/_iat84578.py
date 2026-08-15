import struct, pathlib
pe = bytearray(pathlib.Path("build_univ227/cmd_univ12.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
opt = e+24
dd0 = opt+112
imp_rva = struct.unpack_from("<I", pe, dd0+8)[0]

def rva_to_off(rva):
    for i in range(ns):
        o=sec+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII", pe, o+8)
        if va<=rva<va+max(vs,rs):
            return rp+(rva-va)
    return None
off=rva_to_off(imp_rva)
names={}
while True:
    ilt,_,_,name_rva,iat=struct.unpack_from("<IIIII", pe, off)
    if not name_rva: break
    dll=pe[rva_to_off(name_rva):].split(b"\0",1)[0].decode()
    j=0
    while True:
        slot=iat+j*8
        thunk=struct.unpack_from("<Q", pe, rva_to_off(slot))[0]
        if not thunk: break
        if thunk&(1<<63):
            nm=f"ord#{thunk&0xffff}"
        else:
            nm=pe[rva_to_off(thunk&0xffffffff)+2:].split(b"\0",1)[0].decode(errors="replace")
        names[slot]=(dll,nm); j+=1
    off+=20
print("84578", names.get(0x84578))
print("28f7b area after stos fix", end=" ")
# show stos site
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", pe, o+8); break
blob=pe[rp:rp+rs]
print(blob[0x28f7b-va:0x28fa0-va].hex())
