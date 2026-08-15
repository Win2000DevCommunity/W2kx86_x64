# Apply geparse fallback + diamond fix on univ227 in-memory style via heal methods
import struct, pathlib, subprocess, sys, os
os.environ["PURE"]="1"
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ227/cmd_pure.exe").read_bytes())
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

# 1) force F4EB retarget at 45862
struct.pack_into("<i", blob, 0x45862-va+1, 0x1d35c - (0x45862+5))
print("45862 ->", hex(0x45862+5+struct.unpack_from("<i",blob,0x45862-va+1)[0]))

# 2) fix diamond 3624d r8=f4eb 1d35c, r9=f5a8 diamond 1d4f4
off = 0x3624d-va
struct.pack_into("<Q", blob, off+19, ib+0x1d35c)
struct.pack_into("<Q", blob, off+29, ib+0x1d4f4)
print("r8/r9", hex(struct.unpack_from("<Q",blob,off+19)[0]), hex(struct.unpack_from("<Q",blob,off+29)[0]))

# also fix other diamonds with ch 0x2e, 0x2f, 0x30 if present
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
# find all mov rdx, 0x2e/2f/30 diamond heads and set callbacks chain
# 1d4f4 is 0x2e -> next should be 1d534 (0x2f), 1d574 (0x30), 1d5b4 (f5ed)
chain = {0x2d: (0x1d35c, 0x1d4f4), 0x2e: (0x1d4f4, 0x1d534), 0x2f: (0x1d534, 0x1d574), 0x30: (0x1d574, 0x1d5b4)}
# verify 1d534 etc exist
for ch,(a,b) in chain.items():
    tip = b"\x48\xc7\xc2" + struct.pack("<I", ch)
    k = 0
    while True:
        j = blob.find(tip, k)
        if j < 0: break
        if j>=10 and blob[j-10:j-8]==b"\x48\xb9" and blob[j+7:j+9]==b"\x49\xb8":
            entry = j-10
            old8=struct.unpack_from("<Q",blob,entry+19)[0]
            old9=struct.unpack_from("<Q",blob,entry+29)[0]
            struct.pack_into("<Q", blob, entry+19, ib+a)
            struct.pack_into("<Q", blob, entry+29, ib+b)
            print("ch",hex(ch),"@",hex(va+entry),"r8",hex(old8),"->",hex(ib+a),"r9",hex(old9),"->",hex(ib+b))
        k=j+1

pe[rp:rp+rs] = blob
pathlib.Path("build_univ227/cmd_fix.exe").write_bytes(pe)
df.suppress_fault_ui()
exe = pathlib.Path("build_univ227/cmd_fix.exe").resolve()
try:
    r = subprocess.run([str(exe),"/c","echo","w2ktest"], capture_output=True, timeout=25, cwd=str(exe.parent),
                       creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    print("exit", hex(r.returncode & 0xFFFFFFFF))
    print("out", repr(r.stdout[:400]))
except subprocess.TimeoutExpired as ex:
    print("HANG", repr((ex.stdout or b"")[:400]))
