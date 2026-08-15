import os, sys, struct, pathlib, subprocess
os.environ["PURE"] = "1"
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ228/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = bytearray(pe[rp:rp+rs])

# Exact nested GEParse diamond chain (x86 FD5D style: self/next stubs)
# 0x2d self=F4EB aux, next=0x2e diamond; ...; 0x30 next=real body
chain = {
    0x3624d: (0x1d35c, 0x1d4f4),  # 0x2d
    0x1d4f4: (0x1d4f4, 0x1d534),  # 0x2e
    0x1d534: (0x1d534, 0x1d574),  # 0x2f
    0x1d574: (0x1d574, 0x1d5b4),  # 0x30 -> body
}
for e0va, (a, b) in chain.items():
    e0 = e0va - va
    assert blob[e0:e0+2] == b"\x48\xb9", hex(e0va)
    old8 = struct.unpack_from("<Q", blob, e0+19)[0]
    old9 = struct.unpack_from("<Q", blob, e0+29)[0]
    struct.pack_into("<Q", blob, e0+19, ib+a)
    struct.pack_into("<Q", blob, e0+29, ib+b)
    print(f"{e0va:05x}: {old8:x},{old9:x} -> {ib+a:x},{ib+b:x}")

pe[rp:rp+rs] = blob
pathlib.Path("build_univ228/cmd_diam9.exe").write_bytes(pe)
df.suppress_fault_ui()
exe = pathlib.Path("build_univ228/cmd_diam9.exe").resolve()
r = subprocess.run([str(exe), "/c", "echo", "w2ktest"], capture_output=True,
                   timeout=30, cwd=str(exe.parent),
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
print("exit", hex(r.returncode & 0xffffffff), "w2ktest", b"w2ktest" in r.stdout)
print(repr(r.stdout[:600]))
if (r.returncode & 0xffffffff) != 0:
    sys.argv = ["dbg_fault.py", str(exe), "/c", "echo", "w2ktest"]
    df.main()
