import struct, pathlib, shutil
src=pathlib.Path('build_univ53/cmd_heal4.exe'); dst=pathlib.Path('build_univ53/cmd_heal5.exe')
shutil.copy2(src,dst); pe=bytearray(dst.read_bytes())
e=struct.unpack_from('<I',pe,0x3C)[0]
nsec=struct.unpack_from('<H',pe,e+6)[0]; szopt=struct.unpack_from('<H',pe,e+20)[0]; soff=e+24+szopt
for i in range(nsec):
 o=soff+i*40; name=pe[o:o+8].split(b'\x00',1)[0]
 vsz,va,rsz,raw=struct.unpack_from('<IIII',pe,o+8)
 if name.startswith(b'.text'):
  tva,traw,trsz=va,raw,rsz; break
out=bytearray(pe[traw:traw+trsz]); cave=0x301f1-tva; nop=bytes([0x90]*24)
print('cave', out[cave:cave+32].hex()); assert out[cave:cave+24]==nop
site=0x13580-tva; pat=bytes.fromhex('66c704460a00cc897008'); assert out[site:site+10]==pat
back=site+10; body=bytes.fromhex('66c704460a00498b470448897008')
body+=bytes([0xe9])+struct.pack('<i', back-(cave+len(body)+5))
out[cave:cave+len(body)]=body
out[site:site+10]=bytes([0xe9])+struct.pack('<i', cave-(site+5))+bytes([0x90]*5)
site2=0x52ba4-tva
if out[site2:site2+10]==pat:
 cave2=0x52c05-tva; back2=site2+10
 body2=bytes.fromhex('66c704460a00498b470448897008')
 body2+=bytes([0xe9])+struct.pack('<i', back2-(cave2+len(body2)+5))
 out[cave2:cave2+len(body2)]=body2
 out[site2:site2+10]=bytes([0xe9])+struct.pack('<i', cave2-(site2+5))+bytes([0x90]*5)
 print('fixed 52ba4')
pe[traw:traw+trsz]=out; dst.write_bytes(pe); print('ok', out[site:site+10].hex())
