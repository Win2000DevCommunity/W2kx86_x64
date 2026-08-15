import struct, pathlib, subprocess, sys, time
import pefile

src = pathlib.Path("build_univ258/cmd_probe_jcc.exe")
dst = pathlib.Path("build_univ258/cmd_probe_fdcc.exe")
pe_bytes = bytearray(src.read_bytes())
e = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
ns = struct.unpack_from("<H", pe_bytes, e + 6)[0]
so = struct.unpack_from("<H", pe_bytes, e + 20)[0]
sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe_bytes[o:o + 5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe_bytes, o + 8)
        break
blob = bytearray(pe_bytes[rp:rp + rs])

def retarget_je(blob, jcc_rva, new_tgt, text_va=0x1000):
    off = jcc_rva - text_va
    assert blob[off] == 0x0F and blob[off+1] == 0x84
    struct.pack_into("<i", blob, off + 2, new_tgt - (jcc_rva + 6))
    print(f"retarget {jcc_rva:06X} -> {new_tgt:06X}")

# Temporary: send both bad jes to success epi 1E742 (x86 FDC3)
retarget_je(blob, 0x1E6BB, 0x1E742)
retarget_je(blob, 0x1E71F, 0x1E742)

pe_bytes[rp:rp + rs] = bytes(blob)
dst.write_bytes(pe_bytes)

# alive test
p = subprocess.Popen([sys.executable, "dbg_fault.py", str(dst)],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(4)
alive = p.poll() is None
print("alive_after_4s", alive, "code", p.returncode)
out = b""
if alive:
    p.terminate()
    out = p.communicate(timeout=3)[0]
else:
    out = p.stdout.read()
text = out.decode("utf-8", "replace")
print(text[-1000:])

# /c still ok?
r = subprocess.run([sys.executable, "dbg_fault.py", str(dst), "/c", "echo", "w2ktest"],
                   capture_output=True, text=True, timeout=30)
print("/c exit", r.returncode)
print([ln for ln in (r.stdout or "").splitlines() if "w2ktest" in ln or "exit" in ln.lower()][-5:])
