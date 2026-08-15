import struct, pathlib, shutil, subprocess, os, sys
sys.path.insert(0,".")
os.environ["PURE"]="1"
from x86x64.translator._healing import HealingMixin
class H(HealingMixin):
    def __init__(self): self._cmd_no_hacks=True
# start from fix3 (before bad pushimm layout)
src=pathlib.Path("build_univ230/cmd_fix3.exe")
dst=pathlib.Path("build_univ230/cmd_fix5.exe")
shutil.copy2(src,dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
blob=bytearray(pe[rp:rp+rs])
n=H()._pure_fix_push_imm_pop_eax_return(blob)
print("fixes", n)
pe[rp:rp+rs]=blob; dst.write_bytes(pe)
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
md=Cs(CS_ARCH_X86,CS_MODE_64)
for insn in md.disasm(bytes(blob)[0xd9bc-va:0xd9bc-va+0x10], ib+0xd9bc):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix5.exe","/c","echo","w2ktest"],capture_output=True,timeout=15)
print("exit",hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:800])
print("w2ktest", "w2ktest" in out)
