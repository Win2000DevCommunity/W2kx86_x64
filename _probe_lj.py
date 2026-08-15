# Restore longjmp at waiter sites on probe; smoke
import struct, pathlib, subprocess, sys, time
import pefile

src = pathlib.Path("build_univ258/cmd_probe_jcc.exe")
dst = pathlib.Path("build_univ258/cmd_probe_lj.exe")
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
wfs = struct.pack("<Q", 0x800845F0)
lj = struct.pack("<Q", 0x80084E78)
# Only retarget the fae0==0 wait sites: movabs rdx, -1 then movabs rax, WFS
fixed = 0
i = 0
while i + 30 < len(blob):
    if blob[i:i+2] == b"\x48\xba" and blob[i+2:i+10] in (
            bytes.fromhex("ffffffffffffffff"), bytes.fromhex("ffffffff00000000")):
        # look for movabs rax, wfs within next 20
        for j in range(i+10, min(i+25, len(blob)-10)):
            if blob[j:j+2] == b"\x48\xb8" and blob[j+2:j+10] == wfs:
                blob[j+2:j+10] = lj
                fixed += 1
                break
    i += 1
print("restored longjmp at INFINITE sites", fixed)
pe_bytes[rp:rp+rs] = bytes(blob)
dst.write_bytes(pe_bytes)

# /c smoke
r = subprocess.run([sys.executable, "dbg_fault.py", str(dst), "/c", "echo", "w2ktest"],
                   capture_output=True, text=True, timeout=30)
print("/c", r.returncode, [ln for ln in (r.stdout or "").splitlines() if "w2ktest" in ln or "exit" in ln][-3:])

# alive
p = subprocess.Popen([sys.executable, "dbg_fault.py", str(dst)],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(3)
print("alive", p.poll() is None, "code", p.returncode)
out = p.communicate(timeout=5)[0] if p.poll() is not None else (p.terminate() or p.communicate(timeout=3)[0])
text = out.decode("utf-8","replace")
# show fault line
for ln in text.splitlines():
    if "EXCEPTION" in ln or "code=" in ln or "off=" in ln or "RSP=" in ln:
        print(ln)
