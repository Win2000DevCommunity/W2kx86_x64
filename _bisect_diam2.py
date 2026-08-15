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
    # Use dbg_fault run if available
    try:
        out = df.run_with_fault(str(path.resolve()), ["/c", "echo", "w2ktest"], timeout=25)
        print(name, out)
    except Exception as e:
        exe = path.resolve()
        r = subprocess.run([str(exe), "/c", "echo", "w2ktest"], capture_output=True,
                           timeout=25, cwd=str(exe.parent),
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        print(name, "exit", hex(r.returncode & 0xffffffff), "out", r.stdout[:80], "err", r.stderr[:80])

pe, ib, va, rs, rp, blob0 = load()
cases = {
 "bisect_a": {0x3624d:(0x1d35c,0x1d4f4), 0x1d4f4:(0x1d4f4,0x1d534)},
 "bisect_b": {0x3624d:(0x1d35c,0x1d4f4), 0x1d4f4:(0x1d4f4,0x1d534), 0x1d534:(0x1d534,0x1d574)},
 "bisect_c": {0x3624d:(0x1d35c,0x1d4f4), 0x1d4f4:(0x1d4f4,0x1d534), 0x1d534:(0x1d534,0x1d574), 0x1d574:(0x1d574,0x1d5b4)},
}
for name, chain in cases.items():
    b = bytearray(blob0)
    apply(b, va, ib, chain)
    smoke(pe, rp, rs, b, name)
