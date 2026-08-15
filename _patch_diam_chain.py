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

# Correct chain from x86:
# 3624d ('-'): self=1d35c F4EB, next=1d4f4
# 1d4f4 ('.'): self=1d4f4, next=1d534
# 1d534 ('/'): self=1d534, next=1d574
# 1d574 ('0'): self=1d574, next=1d5b4 body
chain = {
    0x3624d: (0x1d35c, 0x1d4f4),
    0x1d4f4: (0x1d4f4, 0x1d534),
    0x1d534: (0x1d534, 0x1d574),
    0x1d574: (0x1d574, 0x1d5b4),
}
for e0va, (a, b) in chain.items():
    e0 = e0va - va
    assert blob[e0:e0+2] == b'\x48\xb9', hex(e0va)
    assert blob[e0+17:e0+19] == b'\x49\xb8'
    assert blob[e0+27:e0+29] == b'\x49\xb9'
    print(f"before {e0va:#x}: r8={struct.unpack_from('<Q',blob,e0+19)[0]:#x} r9={struct.unpack_from('<Q',blob,e0+29)[0]:#x}")
    struct.pack_into("<Q", blob, e0+19, ib+a)
    struct.pack_into("<Q", blob, e0+29, ib+b)
    print(f"after  {e0va:#x}: r8={ib+a:#x} r9={ib+b:#x}")

pe[rp:rp+rs] = blob
outp = pathlib.Path("build_univ228/cmd_diam_chain.exe")
outp.write_bytes(pe)
# copy shim
shim = pathlib.Path("build_univ228/w2kshim64.dll")
print("shim", shim.exists())
df.suppress_fault_ui()
print("--- subprocess ---")
r = subprocess.run([str(outp.resolve()), "/c", "echo", "w2ktest"], capture_output=True,
                   timeout=25, cwd=str(outp.parent),
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
print("exit", hex(r.returncode & 0xffffffff))
print("stdout", r.stdout[:200])
print("w2ktest", b"w2ktest" in r.stdout)
