# confirm: only issue is mov rdi,rsi vs mov rdi,rcx
import struct, pathlib, subprocess, sys, os
os.environ["PURE"]="1"
sys.path.insert(0, ".")
import dbg_fault as df
pe = bytearray(pathlib.Path("build_univ227/cmd_univ10.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", pe, o+8); break
blob=bytearray(pe[rp:rp+rs])
# patch mov rdi,rsi -> mov rdi,rcx at 28f9a
assert blob[0x28f9a-va:0x28f9a-va+3]==bytes.fromhex("4889f7")
blob[0x28f9a-va:0x28f9a-va+3]=bytes.fromhex("4889cf")
pe[rp:rp+rs]=blob
pathlib.Path("build_univ227/cmd_univ11.exe").write_bytes(pe)
df.suppress_fault_ui()
exe=pathlib.Path("build_univ227/cmd_univ11.exe").resolve()
r=subprocess.run([str(exe),"/c","echo","w2ktest"],capture_output=True,timeout=25,cwd=str(exe.parent),creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
print("exit",hex(r.returncode&0xffffffff))
print(repr(r.stdout[:900]))
if (r.returncode&0xffffffff)!=0:
    sys.argv=["dbg_fault.py",str(exe),"/c","echo","w2ktest"]
    df.main()
