import struct
from pathlib import Path
from x86x64.pe import PE32Image
from x86x64.translator import Win2000Translator

# Apply snap helpers to existing binary's .text
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
n1 = t._fix_calls_into_movabs_imm(text)
n2 = t._snap_calls_back_to_nearby_prologue(text)
n3 = 0
for i in range(len(text)-5):
    if text[i]!=0xe8: continue
    rel=struct.unpack_from("<i",text,i+1)[0]
    tgt=i+5+rel
    snapped=t._pure_snap_chkstk_home_spill_entry(text, tgt)
    if snapped!=tgt:
        struct.pack_into("<i", text, i+1, snapped-(i+5)); n3+=1
print("fixed movabs", n1, "near_pro", n2, "chkstk", n3)
# check inner call
for i in range(0x49a80-trva, 0x49aA0-trva):
    if text[i]==0xe8:
        t=(trva+i+5+struct.unpack_from("<i",text,i+1)[0])&0xffffffff
        print("call", hex(trva+i), "->", hex(t), text[t-trva:t-trva+4].hex())
blob[traw:traw+tsz]=text
out=Path("build_univ10_snap/cmd_pure.exe")
out.parent.mkdir(exist_ok=True)
out.write_bytes(blob)
shim=Path("build_univ10/w2kshim64.dll")
if shim.exists():
    import shutil; shutil.copy(shim, out.with_name("w2kshim64.dll"))
