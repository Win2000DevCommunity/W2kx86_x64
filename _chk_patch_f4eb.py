import struct, pathlib, subprocess, sys
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ225/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
# retarget call at 45862 from 1ea3c to 1d35c
call_at = 0x45862
old = struct.unpack_from("<i", pe, rp + (call_at - va) + 1)[0]
cur = call_at + 5 + old
print("old target", hex(cur))
new_tgt = 0x1d35c
struct.pack_into("<i", pe, rp + (call_at - va) + 1, new_tgt - (call_at + 5))
outp = pathlib.Path("build_univ225/cmd_f4eb.exe")
outp.write_bytes(pe)
# also copy shim
import shutil
shutil.copy("build_univ225/w2kshim64.dll", "build_univ225/w2kshim64.dll")
df.suppress_fault_ui()
try:
    r = subprocess.run([str(outp.resolve()), "/c", "echo", "w2ktest"],
                       capture_output=True, timeout=20, cwd=str(outp.parent),
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    print("exit", hex(r.returncode & 0xFFFFFFFF))
    print("out", repr(r.stdout[:200]))
except subprocess.TimeoutExpired as e:
    print("HANG", repr((e.stdout or b"")[:200]))
