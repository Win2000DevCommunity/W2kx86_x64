import struct, pathlib
pe=pathlib.Path("build_univ230/cmd_both.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
opt=e+24
# PE32+ magic 0x20b
magic=struct.unpack_from("<H",pe,opt)[0]
print("magic", hex(magic))
# import dir: for PE32+ data directories start at opt+112
dd_off = opt + 112
imp_rva=struct.unpack_from("<I",pe,dd_off+8)[0]
iat_rva=struct.unpack_from("<I",pe,dd_off+12*8)[0]  # dir 12 is IAT
print("imp",hex(imp_rva),"iat",hex(iat_rva))

def rva_to_off(rva):
    ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
    for i in range(ns):
        o=sec+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        if va <= rva < va+max(vs,rs):
            return rp+(rva-va)
    return None

# walk import descriptors
off=rva_to_off(imp_rva)
while True:
    oft,timedate,fwd,name,ft=struct.unpack_from("<IIIII",pe,off)
    if oft==0 and name==0: break
    dll=pe[rva_to_off(name):].split(b"\0")[0]
    # walk IAT at ft
    iat=ft; idx=0
    while True:
        io=rva_to_off(iat+idx*8)
        thunk=struct.unpack_from("<Q",pe,io)[0]
        if thunk==0: break
        slot_rva=iat+idx*8
        if slot_rva == 0x85570:
            if thunk & (1<<63):
                print("ordinal", thunk & 0xffff, "dll", dll)
            else:
                no=rva_to_off(thunk)
                hint_name=pe[no+2:].split(b"\0")[0]
                print("FOUND", hint_name, "dll", dll, "slot", hex(slot_rva))
        idx+=1
    off+=20
