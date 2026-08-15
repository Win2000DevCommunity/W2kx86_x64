"""Apply diamond+debs heals to univ230 using live translator maps if possible.
Fallback: copy diam tips + debs already on cmd_both; just re-run heals on pure.
"""
import os, struct, pathlib, shutil, subprocess, sys
os.environ["PURE"]="1"
sys.path.insert(0, ".")

# Post-hoc: start from cmd_pure, apply both heals with a minimal host that
# has pe/rva_map from a quick translate is too slow.  Instead copy diam tips
# from cmd_diam (known good) + run debs heal, then also try running diamond
# heal if we can load rva dump.

src = pathlib.Path("build_univ230/cmd_pure.exe")
dst = pathlib.Path("build_univ230/cmd_fix2.exe")
shutil.copy2(src, dst)
pe = bytearray(dst.read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break

# copy good diamond tips from diam
diam = bytearray(pathlib.Path("build_univ229/cmd_diam.exe").read_bytes())
for tip in [0x3624d, 0x1d4f4, 0x1d534, 0x1d574]:
    off = rp + (tip - va)
    pe[off:off+0x40] = diam[off:off+0x40]

blob = bytearray(pe[rp:rp+rs])
from x86x64.translator._healing import HealingMixin
class H(HealingMixin):
    def __init__(self):
        self._cmd_no_hacks = True
n = H()._pure_fix_delayed_edi_ebx_callee_saves(blob)
print("debs", n)
pe[rp:rp+rs] = blob
dst.write_bytes(pe)

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
code = bytes(blob)
for tip in [0x3624d, 0x1d574]:
    print(f"-- {tip:#x} --")
    for insn in md.disasm(code[tip-va:tip-va+0x30], ib+tip):
        if insn.mnemonic == "movabs" and ("r8" in insn.op_str or "r9" in insn.op_str):
            print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

os.chdir("build_univ230")
r = subprocess.run(["cmd_fix2.exe","/c","echo","w2ktest"], capture_output=True, timeout=15)
print("exit", hex(r.returncode & 0xffffffff))
out = r.stdout.decode("utf-8","replace")
print(out[:500])
print("w2ktest", "w2ktest" in out)
