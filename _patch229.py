import struct, pathlib, subprocess, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
from x86x64.pe import PE32Image
from x86x64.translator import Win2000Translator

src = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
pe = bytearray(pathlib.Path("build_univ229/cmd_pure.exe").read_bytes())
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

# Build minimal translator for heal
pe32 = PE32Image(src.read_bytes())
# Use posthoc known-good chain as quick proof, then heal on copy
chain = {
    0x3624d: (0x1d35c, 0x1d4f4),
    0x1d4f4: (0x1d4f4, 0x1d534),
    0x1d534: (0x1d534, 0x1d574),
    0x1d574: (0x1d574, 0x1d5b4),
}
for e0va,(a,b) in chain.items():
    e0=e0va-va
    struct.pack_into("<Q", blob, e0+19, ib+a)
    struct.pack_into("<Q", blob, e0+29, ib+b)
    print(f"patched {e0va:#x}")

pe[rp:rp+rs]=blob
outp=pathlib.Path("build_univ229/cmd_diam.exe")
outp.write_bytes(pe)
df.suppress_fault_ui()
r=subprocess.run([str(outp.resolve()),"/c","echo","w2ktest"],capture_output=True,timeout=25,cwd=str(outp.parent),creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
print("exit", hex(r.returncode & 0xffffffff))
print("stdout", r.stdout[:300])
print("w2ktest", b"w2ktest" in r.stdout)
