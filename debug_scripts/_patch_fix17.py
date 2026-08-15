import pathlib, struct, shutil, subprocess, os, sys, ctypes as C
sys.path.insert(0,".")
import dbg_fault as df

src=pathlib.Path("build_univ230/cmd_fix16.exe")
dst=pathlib.Path("build_univ230/cmd_fix17.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break

# NOP SEH setup at c954, replace with sub rsp,0x20
off=rp+(0xc954-va)
seh=pe[off:off+43]
print("seh", seh.hex())
# expect starts with 6aff
assert seh[:2]==bytes.fromhex("6aff")
repl=bytes.fromhex("4883ec20") + b"\x90"*39
assert len(repl)==43
pe[off:off+43]=repl

dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix17.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace", errors="replace")
print(out[:2000])
print("has w2ktest", "w2ktest" in out)
