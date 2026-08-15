import struct, pathlib
pe=pathlib.Path("build_univ54/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]; szopt=struct.unpack_from("<H",pe,e+20)[0]; soff=e+24+szopt
for i in range(nsec):
    o=soff+i*40; name=pe[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",pe,o+8)
    if name.startswith(b".text"):
        tva,traw,trsz=va,raw,rsz; break
out=pe[traw:traw+trsz]
rmap={}
for line in open("build_univ54/rva.txt"):
    a,b=line.split(); rmap[int(a,16)]=int(b,16)
print("b627 map", hex(rmap.get(0xb627,0)))
off=rmap.get(0xb627,0)
if off:
    print("at map", out[off:off+32].hex())
print("195d2 map", hex(rmap.get(0x195d2,0)))
off=rmap.get(0x195d2,0)
if off:
    print("195d2", out[off:off+40].hex())
    for d in range(0,16):
        if out[off+d:off+d+4]==bytes.fromhex("4883f900"):
            print("cmp at", hex(off+d), out[off+d:off+d+24].hex()); break
n=0
for i in range(len(out)-16):
    if out[i:i+4]==bytes.fromhex("4883f900") and out[i+4]==0x75:
        work=i+6+struct.unpack_from("<b",out,i+5)[0]
        if 0<=work<len(out) and out[work]==0xc3:
            n+=1
            if n<=5: print("bare short", hex(tva+i))
print("bare short count", n)
# ret sleds near b627 map
off=rmap.get(0xb627,0)
if off:
    for d in range(0,80):
        if out[off+d]==0xc3:
            n=0
            while off+d+n < len(out) and out[off+d+n] in (0xc3,0x90): n+=1
            if n>=22:
                print("sled at", hex(off+d), n); break