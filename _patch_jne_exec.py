import struct, pathlib, subprocess, sys
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ228/full.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = bytearray(pe[rp:rp+rs])

# 17c48: jne 48900 ? should be jne 17c71
at = 0x17c48 - va
print("bytes", blob[at:at+6].hex())
assert blob[at:at+2] == b'\x0f\x85'
old = struct.unpack_from('<i', blob, at+2)[0]
print("old tgt", hex(0x17c48+6+old))
new_tgt = 0x17c71
struct.pack_into('<i', blob, at+2, new_tgt - (0x17c48+6))
print("new tgt", hex(0x17c48+6+struct.unpack_from('<i', blob, at+2)[0]))

pe[rp:rp+rs] = blob
outp = pathlib.Path("build_univ228/cmd_jne.exe")
outp.write_bytes(pe)
df.suppress_fault_ui()
r = subprocess.run([str(outp.resolve()), "/c", "echo", "w2ktest"], capture_output=True,
                   timeout=25, cwd=str(outp.parent),
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
print("exit", hex(r.returncode & 0xffffffff))
print("stdout", r.stdout[:400])
print("w2ktest", b"w2ktest" in r.stdout)
try:
    print("utf16", r.stdout.decode("utf-16le", errors="replace")[:200])
except Exception:
    pass
