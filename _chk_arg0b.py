import struct, pathlib, subprocess, sys, os, ctypes
from ctypes import wintypes
os.environ["PURE"]="1"
sys.path.insert(0, ".")
import dbg_fault as df

exe = pathlib.Path("build_univ227/cmd_univ3.exe").resolve()
# find fault via dbg_fault if available
if hasattr(df, "run_catch"):
    pass
# use existing helper patterns
pe = bytearray(pathlib.Path(exe).read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = pe[rp:rp+rs]
print("fbe4 around 1e2d0", blob[0x1e2d0-va:0x1e2e0-va].hex())
print("homes", blob[0x1e2c0-va:0x1e2d8-va].hex())

# list all 4c89c7 and 4889cf after homes pattern
pat = bytes.fromhex("488987800000004889af880000004889b7900000004889bf98000000415341554156")
# simpler: search 4c89c7
k=0
while True:
    j=blob.find(b"\x4c\x89\xc7", k)
    if j<0: break
    print("4c89c7 at", hex(va+j), "prev", blob[j-20:j].hex())
    k=j+1
k=0
while True:
    j=blob.find(b"\x48\x89\xcf", k)
    if j<0: break
    print("4889cf at", hex(va+j))
    k=j+1
