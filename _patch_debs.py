"""Post-hoc apply delayed edi/ebx heal on univ230 and smoke."""
import struct, pathlib, shutil, subprocess, os, sys
sys.path.insert(0, ".")
os.environ["PURE"] = "1"

# Minimal mixin host to call the heal
from x86x64.translator._healing import HealingMixin

class H(HealingMixin):
    def __init__(self):
        self._cmd_no_hacks = True

src = pathlib.Path("build_univ230/cmd_pure.exe")
dst = pathlib.Path("build_univ230/cmd_debs.exe")
shutil.copy2(src, dst)
pe = bytearray(dst.read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = bytearray(pe[rp:rp+rs])
h = H()
n = h._pure_fix_delayed_edi_ebx_callee_saves(blob)
print("healed", n)
pe[rp:rp+rs] = blob
dst.write_bytes(pe)

# verify
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
md = Cs(CS_ARCH_X86, CS_MODE_64)
code = bytes(blob)
for insn in md.disasm(code[0x24a0d-va:0x24a0d-va+0x30], ib+0x24a0d):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
print("--- epi ---")
for insn in md.disasm(code[0x24e12-va:0x24e12-va+8], ib+0x24e12):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

# smoke
os.chdir("build_univ230")
r = subprocess.run(["cmd_debs.exe", "/c", "echo", "w2ktest"], capture_output=True, timeout=12)
print("exit", hex(r.returncode & 0xffffffff))
print("out", r.stdout.decode("utf-8", "replace")[:300])
print("has w2ktest", b"w2ktest" in r.stdout)
