import struct, pathlib, os, sys
os.environ["PURE"]="1"
sys.path.insert(0,".")
# Count nop sleds
pe=bytearray(pathlib.Path("build_univ55/cmd_pure.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]; sz=struct.unpack_from("<H",pe,e+20)[0]; so=e+24+sz
for i in range(nsec):
    o=so+i*40; name=pe[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",pe,o+8)
    if name.startswith(b".text"):
        tva,traw,trsz=va,raw,rsz; break
out=pe[traw:traw+trsz]
sleds=[]
i=0
while i<len(out):
    if out[i] not in (0x90,0xc3,0xcc):
        i+=1; continue
    j=i; k=out[i]
    while j<len(out) and out[j]==k: j+=1
    if j-i>=24: sleds.append((hex(tva+i), j-i, hex(k)))
    i=j
print("sleds", sleds[:20], "count", len(sleds))
# x86 forwarder present?
src=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3C)[0]
nsec=struct.unpack_from("<H",src,e+6)[0]; sz=struct.unpack_from("<H",src,e+20)[0]; so=e+24+sz
for i in range(nsec):
    o=so+i*40; name=src[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",src,o+8)
    if name.startswith(b".text"):
        text=src[raw:raw+rsz]; text_rva=va; break
pat=b"\xff\x74\x24\x0c"*3+b"\xff\x15"
print("forwarders", text.find(pat), text.count(pat[:4]))  # rough
fo=0xb627-text_rva
print("b627 bytes", text[fo:fo+20].hex())