import os, sys, struct, pathlib
os.environ["PURE"]="1"
sys.path.insert(0,".")
from x86x64.translator.core import Translator
from x86x64.pe.pe32 import PE32Image

src=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
# minimal: just test iat resolve helpers via a half-built approach
# Instead patch univ55 in-place by calling the mixin method on a duck object

pe=bytearray(pathlib.Path("build_univ55/cmd_pure.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]; sz=struct.unpack_from("<H",pe,e+20)[0]; so=e+24+sz
sections=[]
for i in range(nsec):
    o=so+i*40; name=pe[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",pe,o+8)
    sections.append((name,va,vsz,raw,rsz))
    if name.startswith(b".text"):
        tva,traw,trsz=va,raw,rsz
    if name.startswith(b".idata"):
        iva,iraw,irsz=va,raw,rsz
out=bytearray(pe[traw:traw+trsz])
rmap={}
for line in open("build_univ55/rva.txt"):
    a,b=line.split(); rmap[int(a,16)]=int(b,16)

# Build iat map from pe imports
import pefile
p=pefile.PE(data=bytes(pe))
iat_map={}  # old? we only have new
slots={}
for exp in p.DIRECTORY_ENTRY_IMPORT:
  for imp in exp.imports:
    if imp.name:
      slots[imp.name]=imp.address
print("wcsncpy", hex(slots[b"wcsncpy"]))

# Simulate _is_forwarder + cave
text_src=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e2=struct.unpack_from("<I",text_src,0x3C)[0]
nsec2=struct.unpack_from("<H",text_src,e2+6)[0]; sz2=struct.unpack_from("<H",text_src,e2+20)[0]; so2=e2+24+sz2
for i in range(nsec2):
    o=so2+i*40; name=text_src[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",text_src,o+8)
    if name.startswith(b".text"):
        td,tr=text_src[raw:raw+rsz],va; break
fo=0xb627-tr
print("is fwd", td[fo:fo+12]==b"\xff\x74\x24\x0c"*3, td[fo+12:fo+14]==b"\xff\x15")
iat_va=struct.unpack_from("<I",td,fo+14)[0]
print("old iat va", hex(iat_va))

# check old iat name in x86
px=pefile.PE(data=text_src)
for exp in px.DIRECTORY_ENTRY_IMPORT:
  for imp in exp.imports:
    if imp.address==iat_va:
      print("x86 import", exp.dll, imp.name)