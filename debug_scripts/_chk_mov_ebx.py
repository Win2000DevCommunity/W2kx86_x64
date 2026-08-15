from pathlib import Path
import struct
data=Path("build_univ20/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break
# 89 d8 = mov eax, ebx; also 89 d8 before pops 5f5e5d5b
pat=b"\x89\xd8\x5f\x5e\x5d\x5b"
i=0; n=0
while n<10:
    j=text.find(pat,i)
    if j<0: break
    print(f"found at pe {text_rva+j:#x}")
    i=j+1; n+=1
# also 89 d8 alone near 35f00
pat=b"\x89\xd8"
i=text.find(pat, 0x35f00-text_rva)
print("near 35f00", hex(text_rva+i) if i>=0 else None, text[i:i+12].hex() if i>=0 else None)
