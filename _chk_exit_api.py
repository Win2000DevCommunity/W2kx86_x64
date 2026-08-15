import struct
from pathlib import Path
from tools.audit_calls import read_text_section
pe=Path("build_univ6/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3c)[0]
num=struct.unpack_from("<H",pe,e+6)[0]; soh=struct.unpack_from("<H",pe,e+20)[0]
opt=e+24; sec=e+24+soh
# import name for 0x8a548
def rva_to_off(rva):
    for i in range(num):
        o=sec+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
    return None
idd=struct.unpack_from("<I",pe,opt+120)[0]
off=rva_to_off(idd)
while True:
    ilt,_,_,name_rva,iat=struct.unpack_from("<IIIII",pe,off)
    if not name_rva: break
    dll=pe[rva_to_off(name_rva):].split(b"\0")[0]
    iat_off=rva_to_off(iat); idx=0
    while True:
        thunk=struct.unpack_from("<Q",pe,iat_off+idx*8)[0]
        if not thunk: break
        if iat+idx*8==0x8a548:
            hint=struct.unpack_from("<Q",pe,rva_to_off(ilt or iat)+idx*8)[0]&0x7fffffffffffffff
            nm=pe[rva_to_off(hint)+2:].split(b"\0")[0]
            print("API", dll, nm)
        idx+=1
        if idx>500: break
    off+=20
