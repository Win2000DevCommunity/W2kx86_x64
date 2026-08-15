import os, sys, struct, pathlib, shutil
os.environ["PURE"]="1"
sys.path.insert(0,".")
from x86x64.translator.core import Win2000Translator
from x86x64.pe.pe32 import PE32Image

src_path=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
pe32=PE32Image(src_path.read_bytes())
t=Win2000Translator(pe32, win10_test_shim=True)
t.new_base=0x80000000
t._cmd_no_hacks=True
src=pathlib.Path("build_univ56/cmd_pure.exe")
dst=pathlib.Path("build_univ56/cmd_fwd.exe")
shutil.copy2(src,dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]; sz=struct.unpack_from("<H",pe,e+20)[0]; so=e+24+sz
for i in range(nsec):
    o=so+i*40; name=pe[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",pe,o+8)
    if name.startswith(b".text"):
        tva,traw,trsz=va,raw,rsz
    if name.startswith(b".idata"):
        idata_rva=va
out=bytearray(pe[traw:traw+trsz])
rmap={}
for line in open("build_univ56/rva.txt"):
    a,b=line.split(); rmap[int(a,16)]=int(b,16)
rmap_off={k:(v-tva if v>=tva else v) for k,v in rmap.items()}
t._iat_rva_map=t._plan_import_iat_map(idata_rva)
for sec in pe32.sections:
    if sec["flags"] & 0x20000000 and sec["raw_sz"]:
        text_data=pe32.get_section_data(sec); text_rva=sec["vaddr"]; break
t._pure_heal_text_rva=text_rva
n=t._pure_rematerialize_iat_stdcall_forwarders(out, rmap_off, text_data, text_rva)
n2=t._pure_rematerialize_nullcheck_iat_wrappers(out, rmap_off, text_data, text_rva)
n3=t._fix_jccs_into_movabs_imm(out)
n4=t._pure_fix_int3_after_wchar_newline_store(out, rmap_off, text_data, text_rva)
print("fwd",n,"null",n2,"jcc",n3,"nl",n4)
pe[traw:traw+trsz]=out
dst.write_bytes(pe)