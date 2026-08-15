import struct, pathlib
src = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
x86 = src.read_bytes()
e = struct.unpack_from("<I", x86, 0x3C)[0]
ns = struct.unpack_from("<H", x86, e+6)[0]
so = struct.unpack_from("<H", x86, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if x86[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", x86, o+8)
        text_data = x86[rp:rp+rs]; text_rva = va; break

aux_list = []
for off in range(len(text_data)-13):
    if (text_data[off]==0x83 and text_data[off+1]==0x3D and text_data[off+6]==0
        and text_data[off+7]==0x56 and text_data[off+8:off+13]==b"\xbe\x00\x40\x00\x00"):
        aux_list.append(text_rva+off)
print("aux x86", [hex(a) for a in aux_list])
for aux_rva in aux_list:
    for off in range(len(text_data)-5):
        if text_data[off]!=0xE8: continue
        rel=struct.unpack_from("<i",text_data,off+1)[0]
        tgt=(text_rva+off+5+rel)&0xffffffff
        if abs(((tgt-aux_rva+0x80000000)&0xffffffff)-0x80000000)<8:
            print("  call", hex(text_rva+off), "->", hex(tgt))

pe=bytearray(pathlib.Path("build_univ227/cmd_pure.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]; ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
 o=sec+i*40
 if pe[o:o+5]==b".text":
  vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
out=bytearray(pe[rp:rp+rs])
tip=b"\x48\xc7\xc6\x00\x40\x00\x00"
j=out.find(tip)
print("pe64 mov rsi,4000 at", hex(va+j))
print("before", out[max(0,j-24):j].hex())
# check align stub pro at 45855
from x86x64.translator._healing import HealingMixin
# can't easily - just print bytes at 45855
print("45855", out[0x45855-va:0x45855-va+20].hex())
