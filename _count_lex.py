import struct, pathlib
from x86x64.translator._healing import HealingMixin
import pefile

# Count how many lexer sites the heal would match on a clean univ257 (pre-lexer) 
# Use univ257 pure and only apply sticky/lexer to see count
class T(HealingMixin): pass
pe=bytearray(pathlib.Path("build_univ257/cmd_pure.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
blob=bytearray(pe[rp:rp+rs])
homes=bytes.fromhex("48894c240848895424104c894424184c894c2420")
sites=[]
i=0
while True:
    at=blob.find(homes,i)
    if at<0: break
    window=blob[at+20:at+20+0x30]
    for k in range(len(window)-10):
        if window[k:k+2]==b"\x49\xbb":
            v=struct.unpack_from("<Q",window,k+2)[0]
            if (v&0xFFFF) in (0xBAE0,0xBAE4):
                sites.append(at+va); break
    i=at+1
print("lexer-like sites", len(sites), [hex(s) for s in sites[:20]])

# On univ258 - how many jmps to sticky caves (lexer exits)?
pe2=pefile.PE("build_univ258/cmd_pure.exe")
text=pe2.get_data(0x1000,0x57000)
# find cmp sticky,2 ; jb pattern in caves
pat=bytes.fromhex("41833b0272")
idx=0; caves=[]
while True:
    p=text.find(pat, idx)
    if p<0: break
    caves.append(p+0x1000); idx=p+1
print("sticky>=2 caves", [hex(c) for c in caves])
