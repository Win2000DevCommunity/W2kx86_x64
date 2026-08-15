import struct, pathlib, subprocess, sys
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ225/cmd_both.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
# 3624d: movabs rcx @+0, mov rdx @+10, movabs r8 @+17, movabs r9 @+27
off = rp + (0x3624d - va)
print("r8 was", hex(struct.unpack_from("<Q", pe, off+19)[0]))
print("r9 was", hex(struct.unpack_from("<Q", pe, off+29)[0]))
struct.pack_into("<Q", pe, off+19, 0x8001d35c)  # f4eb
struct.pack_into("<Q", pe, off+29, 0x8001d4f4)  # f5a8 diamond
pathlib.Path("build_univ225/cmd_dia.exe").write_bytes(pe)
df.suppress_fault_ui()
exe = pathlib.Path("build_univ225/cmd_dia.exe").resolve()
try:
    r = subprocess.run([str(exe), "/c", "echo", "w2ktest"], capture_output=True,
                       timeout=20, cwd=str(exe.parent),
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    print("exit", hex(r.returncode & 0xFFFFFFFF))
    print("out", repr(r.stdout[:400]))
except subprocess.TimeoutExpired as ex:
    print("HANG", repr((ex.stdout or b"")[:400]))
