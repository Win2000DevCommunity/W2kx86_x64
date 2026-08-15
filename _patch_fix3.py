import struct, pathlib, shutil, subprocess, os, sys
sys.path.insert(0,".")
os.environ["PURE"]="1"
from x86x64.translator._healing import HealingMixin
class H(HealingMixin):
    def __init__(self):
        self._cmd_no_hacks=True

src=pathlib.Path("build_univ230/cmd_fix2.exe")
dst=pathlib.Path("build_univ230/cmd_fix3.exe")
shutil.copy2(src,dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
blob=bytearray(pe[rp:rp+rs])
n=H()._pure_fix_movzx_wchar_arg_after_partial_ax(blob)
print("movzx fixes", n)
pe[rp:rp+rs]=blob
dst.write_bytes(pe)
# verify d59c
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
md=Cs(CS_ARCH_X86,CS_MODE_64)
for insn in md.disasm(bytes(blob)[0xd58b-va:0xd58b-va+0x30], ib+0xd58b):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix3.exe","/c","echo","w2ktest"],capture_output=True,timeout=15)
print("exit",hex(r.returncode&0xffffffff))
print(r.stdout.decode("utf-8","replace")[:600])
print("w2ktest", b"w2ktest" in r.stdout)
