import struct, pathlib
pe=pathlib.Path("build_univ230/cmd_fix2.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
# call at 3206e: ff 15 disp32, next=32074
fo=rp+(0x3206e-va)
assert pe[fo]==0xff and pe[fo+1]==0x15
disp=struct.unpack_from("<i",pe,fo+2)[0]
slot=0x80000000+0x32074+disp
print("slot", hex(slot), "rva", hex(slot-0x80000000))
# name
opt=e+24; imp_rva=struct.unpack_from("<I",pe,opt+112+8)[0]
def rva_to_off(rva):
    for i in range(ns):
        o=sec+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
    return None
off=rva_to_off(imp_rva)
while True:
    oft,td,fwd,name,ft=struct.unpack_from("<IIIII",pe,off)
    if oft==0 and name==0: break
    iat,idx=ft,0
    while True:
        io=rva_to_off(iat+idx*8)
        thunk=struct.unpack_from("<Q",pe,io)[0]
        if thunk==0: break
        if iat+idx*8==slot-0x80000000:
            nm=pe[rva_to_off(thunk)+2:].split(b"\0")[0]
            print("API", nm)
        idx+=1
    off+=20
