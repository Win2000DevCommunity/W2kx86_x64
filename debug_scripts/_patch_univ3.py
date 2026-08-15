import struct, shutil
from pathlib import Path
from tools.audit_calls import read_text_section

src = Path("build_univ3/cmd_pure.exe")
dst = Path("build_univ3_patch/cmd_pure.exe")
dst.parent.mkdir(exist_ok=True)
shutil.copy(src, dst)
# also copy shim
shim = src.with_name("w2kshim64.dll")
if shim.exists():
    shutil.copy(shim, dst.with_name("w2kshim64.dll"))

blob = bytearray(dst.read_bytes())
# find .text
e = struct.unpack_from("<I", blob, 0x3c)[0]
num = struct.unpack_from("<H", blob, e+6)[0]
soh = struct.unpack_from("<H", blob, e+20)[0]
sec = e+24+soh
trva=traw=tsz=0
for i in range(num):
    o=sec+i*40
    if blob[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", blob, o+8)
        trva,traw,tsz=va,rp,rs
        break
data=memoryview(blob)[traw:traw+tsz]

# Real entry for cmp rcx,0 helper
real = 0x2fdcc
bad = 0x31e85
fixed=0
for i in range(tsz-5):
    if data[i]!=0xE8: continue
    t=(trva+i+5+struct.unpack_from("<i", data, i+1)[0])&0xffffffff
    if t==bad:
        struct.pack_into("<i", blob, traw+i+1, real-(trva+i+5))
        fixed+=1
print("patched", fixed, "calls", hex(bad), "->", hex(real))
dst.write_bytes(blob)
