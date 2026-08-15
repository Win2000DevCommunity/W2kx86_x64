import pathlib, struct, shutil, subprocess, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

src=pathlib.Path("build_univ230/cmd_fix5.exe")
dst=pathlib.Path("build_univ230/cmd_fix7.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break

def rva_off(rva): return rp+(rva-va)

# Only patch d9bc with 3-pop form
off=rva_off(0xd9bc)
repl=bytes.fromhex("b8010000005f5e5bc9c3")
print("d9bc before", bytes(pe[off:off+10]).hex())
pe[off:off+10]=repl
print("d9bc after", bytes(pe[off:off+10]).hex())

# Fix 2a3f4 with 2-pop form: mov eax,1; pop rdi; pop rsi; nop; leave; ret
off2=rva_off(0x2a3f4)
print("2a3f4 before", bytes(pe[off2:off2+10]).hex())
pe[off2:off2+10]=bytes.fromhex("b8010000005f5e90c9c3")
print("2a3f4 after", bytes(pe[off2:off2+10]).hex())

dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix7.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", r.returncode, hex(r.returncode & 0xffffffff))
print("out", r.stdout.decode("utf-8","replace")[:800])
print("err", r.stderr.decode("utf-8","replace")[:300])
