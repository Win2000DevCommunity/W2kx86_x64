import struct, pathlib, shutil
src=pathlib.Path("build_univ53/cmd_heal5.exe")
dst=pathlib.Path("build_univ53/cmd_heal6.exe")
shutil.copy2(src,dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
szopt=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+szopt
for i in range(nsec):
 o=soff+i*40; name=pe[o:o+8].split(b"\0",1)[0]
 vsz,va,rsz,raw=struct.unpack_from("<IIII",pe,o+8)
 if name.startswith(b".text"):
  tva,traw,trsz=va,raw,rsz; break
out=bytearray(pe[traw:traw+trsz])
off=0x1358e-tva
assert out[off:off+7]==bytes.fromhex("4881c418100000"), out[off:off+7].hex()
out[off:off+7]=bytes.fromhex("4881c468240000")
print("patched", hex(tva+off))
pe[traw:traw+trsz]=out
dst.write_bytes(pe)
