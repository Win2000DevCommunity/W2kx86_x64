import struct, shutil
from pathlib import Path
from x86x64.pe import PE32Image
from x86x64.translator import Win2000Translator

blob = bytearray(Path("build_univ10/cmd_pure.exe").read_bytes())
e=struct.unpack_from("<I",blob,0x3c)[0]
num=struct.unpack_from("<H",blob,e+6)[0]; soh=struct.unpack_from("<H",blob,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if blob[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",blob,o+8); trva,traw,tsz=va,rp,rs; break
text = bytearray(blob[traw:traw+tsz])
pe = PE32Image(Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
t = Win2000Translator(pe, win10_test_shim=True)
t._cmd_no_hacks = True
print("near", t._snap_calls_back_to_nearby_prologue(text))
print("movabs", t._fix_calls_into_movabs_imm(text))
for i in range(0x49a80-trva, 0x49aA0-trva):
    if text[i]==0xe8:
        tg=(trva+i+5+struct.unpack_from("<i",text,i+1)[0])&0xffffffff
        print("call", hex(trva+i), "->", hex(tg), text[tg-trva:tg-trva+4].hex())
blob[traw:traw+tsz]=text
out=Path("build_univ10_snap2/cmd_pure.exe"); out.parent.mkdir(exist_ok=True)
out.write_bytes(blob)
shutil.copy("build_univ10/w2kshim64.dll", out.with_name("w2kshim64.dll"))
