import struct, pathlib, subprocess, sys
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ227/cmd_fbe4.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = bytearray(pe[rp:rp+rs])
# snap 1eb9a: 19da7 -> 19da4
off = 0x1eb9a - va
old = 0x1eb9a+5+struct.unpack_from("<i",blob,off+1)[0]
struct.pack_into("<i", blob, off+1, 0x19da4 - (0x1eb9a+5))
print("1eb9a", hex(old), "-> 19da4")
pe[rp:rp+rs] = blob
pathlib.Path("build_univ227/cmd_echo2.exe").write_bytes(pe)
df.suppress_fault_ui()
exe = pathlib.Path("build_univ227/cmd_echo2.exe").resolve()
try:
    r = subprocess.run([str(exe),"/c","echo","w2ktest"], capture_output=True, timeout=25,
                       cwd=str(exe.parent), creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    print("exit", hex(r.returncode & 0xFFFFFFFF))
    print("out", repr(r.stdout[:500]))
    try:
        print("utf8", r.stdout.decode("utf-8","replace")[:300])
    except: pass
except subprocess.TimeoutExpired as ex:
    print("HANG", repr((ex.stdout or b"")[:500]))
