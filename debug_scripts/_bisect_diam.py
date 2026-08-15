import os, sys, struct, pathlib, subprocess
os.environ["PURE"] = "1"
sys.path.insert(0, ".")
import dbg_fault as df

def load():
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
    return pe, ib, va, rs, rp, bytearray(pe[rp:rp+rs])

def apply(blob, va, ib, chain):
    for e0va, (a, b) in chain.items():
        e0 = e0va - va
        struct.pack_into("<Q", blob, e0+19, ib+a)
        struct.pack_into("<Q", blob, e0+29, ib+b)

def smoke(pe, rp, rs, blob, name):
    pe = bytearray(pe)
    pe[rp:rp+rs] = blob
    path = pathlib.Path(f"build_univ228/{name}.exe")
    path.write_bytes(pe)
    df.suppress_fault_ui()
    exe = path.resolve()
    r = subprocess.run([str(exe), "/c", "echo", "w2ktest"], capture_output=True,
                       timeout=25, cwd=str(exe.parent),
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    print(name, "exit", hex(r.returncode & 0xffffffff), "w2ktest", b"w2ktest" in r.stdout)
    return r

pe, ib, va, rs, rp, blob0 = load()

# A: only top two (out-of-text)
b = bytearray(blob0)
apply(b, va, ib, {0x3624d:(0x1d35c,0x1d4f4), 0x1d4f4:(0x1d4f4,0x1d534)})
smoke(pe, rp, rs, b, "bisect_a")

# B: A + 1d534
b = bytearray(blob0)
apply(b, va, ib, {0x3624d:(0x1d35c,0x1d4f4), 0x1d4f4:(0x1d4f4,0x1d534), 0x1d534:(0x1d534,0x1d574)})
r = smoke(pe, rp, rs, b, "bisect_b")

# C: B + 1d574
b = bytearray(blob0)
apply(b, va, ib, {0x3624d:(0x1d35c,0x1d4f4), 0x1d4f4:(0x1d4f4,0x1d534), 0x1d534:(0x1d534,0x1d574), 0x1d574:(0x1d574,0x1d5b4)})
smoke(pe, rp, rs, b, "bisect_c")

# D: A + 1d534 with next=1d5b4 skip 1d574?
b = bytearray(blob0)
apply(b, va, ib, {0x3624d:(0x1d35c,0x1d4f4), 0x1d4f4:(0x1d4f4,0x1d534), 0x1d534:(0x1d534,0x1d5b4)})
smoke(pe, rp, rs, b, "bisect_d")
