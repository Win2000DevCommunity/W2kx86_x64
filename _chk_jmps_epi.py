import struct, pathlib
pe = bytearray(pathlib.Path("build_univ230/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]; so=struct.unpack_from("<H", pe, e+20)[0]; sec=e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytearray(pe[rp:rp+rs])
# find all E8/E9/jcc to 0x24e12 and 0x24e14
targets={0x24e12, 0x24e14, 0x24e13}
for i in range(len(code)-5):
    if code[i]==0xE9 or code[i]==0xE8:
        rel=struct.unpack_from("<i",code,i+1)[0]
        t=i+5+rel
        if t in targets:
            print(f"{'jmp' if code[i]==0xE9 else 'call'} {ib+va+i:#x} -> {ib+va+t:#x}")
    if code[i]==0x0F and code[i+1] in (0x84,0x85):
        rel=struct.unpack_from("<i",code,i+2)[0]
        t=i+6+rel
        if t in targets:
            print(f"jcc {ib+va+i:#x} -> {ib+va+t:#x}")
