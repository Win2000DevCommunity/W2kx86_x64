import struct, pathlib
pe=pathlib.Path("build_univ55/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]; sz=struct.unpack_from("<H",pe,e+20)[0]; so=e+24+sz
for i in range(nsec):
    o=so+i*40; name=pe[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",pe,o+8)
    if name.startswith(b".text"):
        tva,traw,out=va,raw,pe[raw:raw+rsz]; break
rmap={}
for line in open("build_univ55/rva.txt"):
    a,b=line.split(); rmap[int(a,16)]=int(b,16)
off=rmap.get(0xb627,0)
print("b627", hex(off), out[off:off+32].hex() if off else None)
# search for our stub signature sub rsp,0x28; movabs; ... wcsncpy iat
# find wcsncpy slot
import pefile
p=pefile.PE(data=pe)
slot=None
for e in p.DIRECTORY_ENTRY_IMPORT:
  for imp in e.imports:
    if imp.name==b"wcsncpy":
      slot=imp.address; print("wcsncpy slot", hex(slot))
want=bytes.fromhex("4883ec2848b8")+struct.pack("<Q",slot)
idx=out.find(want)
print("stub at", hex(tva+idx) if idx>=0 else None)