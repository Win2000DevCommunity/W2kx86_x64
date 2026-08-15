import pathlib, struct, shutil, subprocess, os, sys, ctypes as C
sys.path.insert(0,".")
import dbg_fault as df
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)

src=pathlib.Path("build_univ230/cmd_fix14.exe")
dst=pathlib.Path("build_univ230/cmd_fix15.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break

# at 28b88: je 28c15 ? retarget to 28bd0
off=rp+(0x28b88-va)
print("before", pe[off:off+6].hex())
# 0F 84 rel32
assert pe[off]==0x0F and pe[off+1]==0x84
new_tgt = rp+(0x28bd0-va)
struct.pack_into("<i", pe, off+2, new_tgt - (off+6))
print("after", pe[off:off+6].hex(), "->", hex(0x28bd0))

# also: the add rsp,8 after strcpy in non-zero path at 28bc7 - may be spurious
# leave for now

dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix15.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1500])
print("has w2ktest", "w2ktest" in out)
