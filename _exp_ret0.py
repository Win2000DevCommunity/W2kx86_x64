# Compare: at fault time fbe4 returned 1 because early-exit read wrong counter.
# Quick experiment: patch 1e5dd path to xor eax,eax; jmp epilogue and see echo.
import struct, pathlib, subprocess, sys, os
os.environ["PURE"]="1"
sys.path.insert(0, ".")
import dbg_fault as df
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = bytearray(pathlib.Path("build_univ227/cmd_univ4.exe").read_bytes())
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

# At 1e5dd: replace with:
# xor eax,eax
# jmp 47510  (rel32)
# 31 c0
# e9 rel
epi = 0x47510
at = 0x1e5dd - va
blob[at] = 0x31; blob[at+1]=0xc0
rel = epi - (0x1e5dd + 2 + 5)
struct.pack_into("<i", blob, at+2, 0)  # placeholder
blob[at+2] = 0xe9
struct.pack_into("<i", blob, at+3, epi - (0x1e5df + 5))
# wait address after xor is 1e5df, then e9 at 1e5df
# Fix properly:
# 1e5dd: 31 c0          xor eax,eax
# 1e5df: e9 xx xx xx xx jmp epi
blob[at:at+2] = b"\x31\xc0"
blob[at+2] = 0xe9
struct.pack_into("<i", blob, at+3, epi - (0x1e5dd + 7))

pe[rp:rp+rs]=blob
pathlib.Path("build_univ227/cmd_univ5.exe").write_bytes(pe)
df.suppress_fault_ui()
exe=pathlib.Path("build_univ227/cmd_univ5.exe").resolve()
sys.argv=["dbg_fault.py", str(exe), "/c", "echo", "w2ktest"]
df.main()
