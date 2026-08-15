import struct, pathlib, shutil, subprocess, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
src = pathlib.Path("build_univ250/cmd_pure.exe")
dst = pathlib.Path("build_univ250/cmd_probe_je.exe")
shutil.copy2(src, dst)
pe = bytearray(dst.read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]
so = struct.unpack_from("<H", pe, e + 20)[0]
sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe[o:o+5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8)
        break

def off(rva):
    return rp + (rva - va)

# patch je 1d62a -> 1d6cb
j = off(0x1D62A)
assert pe[j:j+2] == bytes([0x0F, 0x84])
struct.pack_into("<i", pe, j + 2, 0x1D6CB - (0x1D62A + 6))
print("je now", hex(0x1D62A + 6 + struct.unpack_from("<i", pe, j + 2)[0]))
dst.write_bytes(pe)
env = os.environ.copy()
env["PATH"] = str(dst.parent) + ";" + env.get("PATH", "")
p = subprocess.run([str(dst), "/c", "echo", "w2ktest"], capture_output=True, timeout=15, env=env)
print("rc", hex(p.returncode & 0xffffffff))
print("out", p.stdout[:500])
print("err", p.stderr[:300])
